"""政务 demo 业务工具 —— 实现 Tool port,经枢衡管线的 Executor 统一执行。

这些工具**不再绕过端口系统**:它们是 `@capability("tool", ...)` 实现,带 `base_risk`(供评分器,
无需枚举工具名)与 `model_schema`(喂模型的规格,源自 gov.TOOL_SCHEMAS 单一真源)。执行逻辑
复用 `gov.execute`(脱敏模拟,enterprise 裸奔 agent 也共用它),本模块只是 Tool 适配层。

注册时机:`demo.runtime` 在 build_pipeline 前 import 本模块即触发 @capability 注册(幂等)。
"""

from __future__ import annotations

from ..core.domain import Context, ExecResult
from ..core.registry import capability
from . import gov

# fn 名 → OpenAI function schema(从 gov.TOOL_SCHEMAS 建索引,保持单一真源)。
_SCHEMA_BY_FN: dict[str, dict] = {s["function"]["name"]: s for s in gov.TOOL_SCHEMAS}


def _schema(fn: str) -> dict | None:
    return _SCHEMA_BY_FN.get(fn)


class _GovTool:
    """政务工具基类:把 gov.execute 的 (ok, text) 归一为 ExecResult。子类只声明元数据。"""

    name: str = ""
    base_risk: float = 0.3
    model_schema: dict | None = None

    def call(self, arguments: dict, ctx: Context) -> ExecResult:
        ok, output = gov.execute(self.name, arguments)
        return ExecResult(ok=True, output=output) if ok else ExecResult(ok=False, error=output)


@capability("tool", "kb.search")
class KbSearchTool(_GovTool):
    name = "kb.search"
    base_risk = 0.1  # 只读检索,风险低
    model_schema = _schema("kb_search")


@capability("tool", "doc.read")
class DocReadTool(_GovTool):
    name = "doc.read"
    base_risk = 0.3  # 读取本身中低,密级/越界由策略按参数拦
    model_schema = _schema("doc_read")


@capability("tool", "citizen.query")
class CitizenQueryTool(_GovTool):
    name = "citizen.query"
    base_risk = 0.45  # 涉公民个人信息
    model_schema = _schema("citizen_query")


@capability("tool", "case.approve")
class CaseApproveTool(_GovTool):
    name = "case.approve"
    base_risk = 0.7  # 业务审批决定
    model_schema = _schema("case_approve")


@capability("tool", "funds.disburse")
class FundsDisburseTool(_GovTool):
    name = "funds.disburse"
    base_risk = 0.8  # 涉财政资金,最高基础风险
    model_schema = _schema("funds_disburse")


@capability("tool", "external.send")
class ExternalSendTool(_GovTool):
    name = "external.send"
    base_risk = 0.6  # 对外发送数据,外泄面
    model_schema = _schema("external_send")


@capability("tool", "shell.exec")
class ShellExecTool(_GovTool):
    name = "shell.exec"
    base_risk = 0.6  # 系统命令
    model_schema = _schema("shell_exec")


@capability("tool", "notify.send")
class NotifySendTool(_GovTool):
    name = "notify.send"
    base_risk = 0.3  # 内部通知
    model_schema = _schema("notify_send")
