"""前置网关 DTO —— /gateway/chat(判恶意→拦截/审核/放行→转发)+ /admin/gateway-config(上游接入)。"""

from __future__ import annotations

from pydantic import BaseModel, Field

from ....core.domain import Disposition

__all__ = [
    "GatewayChatRequest",
    "GatewayFindingDTO",
    "GatewayChatResponse",
    "GatewayConfigWrite",
    "GatewayProbeResponse",
]


# ---- /gateway/chat(前置网关:判恶意 → 拦截/审核/放行 → 转发企业智能体)----
class GatewayChatRequest(BaseModel):
    session_id: str = "anon"
    message: str = Field(min_length=1, max_length=8000)


class GatewayFindingDTO(BaseModel):
    kind: str
    score: float
    severity: str | None = None
    source_type: str | None = None
    matched: list[str] = Field(default_factory=list)


class GatewayChatResponse(BaseModel):
    session_id: str
    decision: Disposition  # allow=放行 / approve=审核挂起 / block=拦截
    risk_level: str
    forwarded: bool  # 是否真正转发给了企业智能体
    reason: str
    max_score: float
    findings: list[GatewayFindingDTO] = Field(default_factory=list)
    reply: str = ""  # 仅放行时为企业智能体的真实回复(出口拦截时为打码占位)
    tools: list[dict] = Field(default_factory=list)  # 企业智能体本轮执行的工具轨迹
    upstream_error: str | None = None
    # 出口闸门:对回复做敏感/危险内容检测后的结论(无回复时为 None)
    output_decision: Disposition | None = None
    output_risk_level: str = ""
    output_reason: str = ""
    output_blocked: bool = False  # 回复是否因出口检测被拦截打码
    output_sanitized: bool = False  # 回复是否经出口脱敏后回传(复核档,仅打码救得了的敏感量)


# ---- /admin/gateway-config(网关上游接入,设置页可配)----
class GatewayConfigWrite(BaseModel):
    """更新上游接入配置。auth_value 为 None=保持不变、""=清空、其它=替换。"""

    enabled: bool = True
    name: str = Field(default="默认上游", max_length=64)
    protocol: str = Field(pattern="^(openai|rest|native)$")
    endpoint: str = Field(min_length=1, max_length=512)
    path: str = Field(default="", max_length=256)
    model: str = Field(default="", max_length=128)
    auth_type: str = Field(default="none", pattern="^(none|bearer|header)$")
    auth_header: str = Field(default="Authorization", max_length=64)
    auth_value: str | None = Field(default=None, max_length=2048)
    timeout_seconds: float = Field(default=60.0, ge=1, le=600)
    verify_tls: bool = True
    rest_message_field: str = Field(default="message", max_length=64)
    rest_response_path: str = Field(default="reply", max_length=128)
    team_id: int | None = None  # 该被保护智能体归属团队(P2 数据隔离);None=全局可见


class GatewayProbeResponse(BaseModel):
    ok: bool
    latency_ms: int
    detail: str
    status_code: int | None = None
