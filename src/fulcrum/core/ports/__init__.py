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
    """出站:真实大模型(OpenAI 兼容)。"""

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
    """证据化来源归因(枢衡脊柱)。"""

    def attribute(
        self, intent: ToolIntent, spans: list[SourceSpan], ctx: Context
    ) -> Attribution: ...


@runtime_checkable
class RiskScorer(Protocol):
    """工具调用风险评分(0~1)。对应赛题目标 2。"""

    def score(self, intent: ToolIntent, ctx: Context) -> float: ...


@runtime_checkable
class ChainAnalyzer(Protocol):
    """任务链 / 轨迹分析(异常链)。对应赛题目标 2。"""

    def analyze(self, session_trace: list[ToolIntent], ctx: Context) -> list[Finding]: ...


@runtime_checkable
class PolicyEngine(Protocol):
    """策略判定 -> 分级处置。对应赛题目标 1/2。"""

    def decide(self, intent: ToolIntent, ctx: Context) -> PolicyDecision: ...


@runtime_checkable
class Tool(Protocol):
    """受控工具。"""

    name: str

    def call(self, arguments: dict, ctx: Context) -> ExecResult: ...


@runtime_checkable
class Executor(Protocol):
    """沙箱执行器:在受控边界内执行高危工具。对应赛题目标 2。"""

    def execute(self, tool: Tool, intent: ToolIntent, ctx: Context) -> ExecResult: ...


@runtime_checkable
class SupplyChainScanner(Protocol):
    """供应链扫描:对 manifest/组件给出评级。对应赛题目标 3。"""

    def scan(self, manifest: dict, ctx: Context) -> ScanReport: ...


@runtime_checkable
class AuditSink(Protocol):
    """防篡改审计落库(hash-chain)。对应赛题目标 4。"""

    def append(self, event: AuditEvent) -> AuditEvent: ...

    def events(self, session_id: str) -> list[AuditEvent]: ...

    def verify_chain(self, session_id: str) -> bool: ...


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
