"""请求级安全上下文 —— 在管线各阶段之间传递的状态载体。"""

from __future__ import annotations

from pydantic import BaseModel, Field

from .enums import RiskLevel
from .models import Finding, SourceSpan, ToolIntent


class Context(BaseModel):
    """**请求级**安全上下文 —— 在单次请求的管线各阶段之间传递的累积状态。

    管线把它在 labeler -> detector -> attributor -> policy -> executor 之间传递,
    各能力只读取/追加,**不持有跨请求状态**。

    生命周期边界(重要):本对象随每个请求新建(见 pipeline 各入口),
    因此 `request_trace` 只累积**本请求内**的多个工具意图(一次模型回复可能触发多次
    工具调用)。**真正的跨请求会话状态当前无归宿** —— 任务链分析(ChainAnalyzer)
    若要看跨请求轨迹,需引入独立的 `SessionStore` port 来持有/喂入;在 ChainAnalyzer
    真实化之前不预建该 port(避免拍脑袋设计签名)。审计链(AuditSink)是另一回事:
    它是只追加的证据流,不是可读写的工作内存。
    """

    session_id: str
    request_id: str | None = None
    trace_id: str | None = None
    spans: list[SourceSpan] = Field(default_factory=list)
    # 请求级动作序列(非跨请求!命名特意不叫 session_trace,见上方生命周期说明)。
    request_trace: list[ToolIntent] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.LOW
