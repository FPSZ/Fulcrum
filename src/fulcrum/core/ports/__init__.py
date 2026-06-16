"""端口 / 抽象接口(Protocol)—— 队友实现功能要对齐的"插槽"。

新增能力 = 新增实现并注册(见 fulcrum.core.registry),**不改本文件、不改 pipeline**。
所有接口只接收/返回 fulcrum.core.domain 的类型。
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..domain import (
    Attribution,
    AuditEvent,
    Context,
    ExecResult,
    Finding,
    ModelRequest,
    ModelResponse,
    PolicyDecision,
    ScanReport,
    SourceSpan,
    ToolIntent,
)


@runtime_checkable
class ModelClient(Protocol):
    """出站:真实大模型(OpenAI 兼容)。

    **立场:缓冲式、非流式(刻意为之,已定契约)。** 安全网关的价值在于"缓冲到可判定单元
    再放行"(arch §7):必须拿到**完整**的模型响应(含完整 tool_calls)才能做归因/评分/策略
    判定与分级处置。逐 token 流式转发会让"边出边检"无法 fail-closed。故 chat() 一次性返回
    完整 ModelResponse,**不提供 chat_stream**。若未来确需对接流式上游,应在**适配器内部**
    缓冲到完整响应后再交给本端口,绝不把流式语义引入管线契约。
    """

    async def chat(self, req: ModelRequest) -> ModelResponse: ...


@runtime_checkable
class SourceLabeler(Protocol):
    """为请求中的各段输入打来源与信任标签。"""

    def label(self, req: ModelRequest) -> list[SourceSpan]: ...


@runtime_checkable
class Detector(Protocol):
    """输入风险检测(注入/越狱/投毒…)。对应赛题目标 1。"""

    name: str

    def detect(self, spans: list[SourceSpan], ctx: Context) -> list[Finding]: ...


@runtime_checkable
class Attributor(Protocol):
    """证据化来源归因(枢衡脊柱)。

    async:既定路线里要接 LLM-judge 后置增强(arch §5),归因是 IO-bound。
    现在统一 async,免得 P3 接模型时回头改整条管线 + 所有实现 + 所有测试。
    """

    async def attribute(
        self, intent: ToolIntent, spans: list[SourceSpan], ctx: Context
    ) -> Attribution: ...


@runtime_checkable
class RiskScorer(Protocol):
    """工具调用风险评分(0~1)。对应赛题目标 2。"""

    def score(self, intent: ToolIntent, ctx: Context) -> float: ...


@runtime_checkable
class ChainAnalyzer(Protocol):
    """任务链 / 轨迹分析(异常链)。对应赛题目标 2。

    async:终局可能查向量库 / 调模型识别异常序列,IO-bound,统一 async。
    入参 `trace` 是**请求级**动作序列(见 Context 生命周期说明);真正的跨请求
    会话状态待 ChainAnalyzer 真实化时引入 SessionStore port 承载,现在不预建。
    """

    async def analyze(self, trace: list[ToolIntent], ctx: Context) -> list[Finding]: ...


@runtime_checkable
class PolicyEngine(Protocol):
    """策略判定 -> 分级处置。对应赛题目标 1/2。

    async:终局可能远程策略服务 / 查向量库,统一 async 留出空间。
    """

    async def decide(self, intent: ToolIntent, ctx: Context) -> PolicyDecision: ...


@runtime_checkable
class Tool(Protocol):
    """受控工具。

    base_risk:工具的**固有基础风险**(0~1)。管线在评分前把它盖戳到 ToolIntent,评分器据此
    叠加参数风险即可,**不再枚举工具名**——加工具零改评分器(加工具 = 写一个 Tool 实现并注册)。
    model_schema:可选的 OpenAI function 声明。有则作为"喂给模型的工具规格"的唯一真源,
    与执行入口共用同一处定义,避免 schema 与实现两处漂移。无需暴露给模型的工具置 None。
    """

    name: str
    base_risk: float
    model_schema: dict | None

    def call(self, arguments: dict, ctx: Context) -> ExecResult: ...


@runtime_checkable
class Executor(Protocol):
    """沙箱执行器:在受控边界内执行高危工具。对应赛题目标 2。

    async:P3 真沙箱(容器 / 受限子进程 + 超时)必然 IO-bound,统一 async。
    """

    async def execute(self, tool: Tool, intent: ToolIntent, ctx: Context) -> ExecResult: ...


@runtime_checkable
class SupplyChainScanner(Protocol):
    """供应链扫描:对 manifest/组件给出评级。对应赛题目标 3。

    定位:**组件登记/上线时**的离线关切,不在每请求安全管线里(故不进 SecurityPipeline 装配与
    fulcrum.yml 必填字段)。真实化时由独立的供应链流程装配调用,接口保持不变。
    """

    def scan(self, manifest: dict, ctx: Context) -> ScanReport: ...


@runtime_checkable
class AuditSink(Protocol):
    """防篡改审计落库(hash-chain)。对应赛题目标 4。

    async:append 是安全关键写入,落库(SQLite/PG)是 IO;且架构 §7 要求"审计写入失败 →
    高危动作默认阻断",故必须 await 到「写成功与否」才放行,不能 fire-and-forget。
    events/verify 同为存储读取,统一 async,免得 P1 落库时回头改全链。
    """

    async def append(self, event: AuditEvent) -> AuditEvent: ...

    async def events(self, session_id: str) -> list[AuditEvent]: ...

    async def verify_chain(self, session_id: str) -> bool: ...


__all__ = [
    "Attributor",
    "AuditSink",
    "ChainAnalyzer",
    "Detector",
    "Executor",
    "ModelClient",
    "PolicyEngine",
    "RiskScorer",
    "SourceLabeler",
    "SupplyChainScanner",
    "Tool",
]
