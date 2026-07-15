"""AI 操作助手 DTO。

旧规划器(/assistant/plan)+ 真 Agent(plan/11:对话/工具/提案/确认/撤销/模型接入)。
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from .chat import ToolCallRequest

__all__ = [
    "AssistantActionDTO",
    "AssistantPlanRequest",
    "AssistantPlanResponse",
    "AssistantChatRequest",
    "AssistantResetRequest",
    "AssistantResetResponse",
    "AssistantToolDTO",
    "AssistantUiDirectiveDTO",
    "AssistantProposedActionDTO",
    "AssistantApprovalRequestDTO",
    "AssistantStepDTO",
    "AssistantChatResponse",
    "AssistantRequestApprovalRequest",
    "AssistantRequestApprovalResponse",
    "AssistantConfirmRequest",
    "AssistantConfirmResponse",
    "ToolCallProposalRequest",
    "AssistantUndoRequest",
    "AssistantUndoResponse",
    "AssistantModelConfigDTO",
    "AssistantModelConfigUpdate",
    "AssistantModelTestRequest",
    "AssistantModelTestResponse",
]


# ---- AI 操作助手(后端大脑)----
class AssistantActionDTO(BaseModel):
    """动作目录条目(供助手面板展示「当前角色能调哪些动作」)。"""

    id: str
    label: str
    description: str
    risk: str
    requires: list[str] = Field(default_factory=list)
    args_hint: str = ""


class AssistantPlanRequest(BaseModel):
    intent: str = Field(min_length=1, max_length=2000)
    session_id: str | None = Field(default=None, max_length=128)


class AssistantPlanResponse(BaseModel):
    """规划结果:选了哪个动作、是否准许、是否需二次确认、为什么。"""

    ok: bool
    reason: str
    action_id: str | None = None
    label: str = ""
    args: dict = Field(default_factory=dict)
    risk: str = ""
    requires_confirmation: bool = False
    denied: bool = False


# ---- AI 操作助手(真 Agent · plan/11)----
class AssistantChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    session_id: str | None = Field(default=None, max_length=128)


class AssistantResetRequest(BaseModel):
    """清空某会话的多轮记忆(新建会话 / 显式清除上下文)。"""

    session_id: str = Field(min_length=1, max_length=128)


class AssistantResetResponse(BaseModel):
    ok: bool = True


class AssistantToolDTO(BaseModel):
    """当前角色可调的一个工具(供助手面板侧栏 + /assistant/tools 列出)。"""

    name: str
    kind: str
    label: str
    description: str
    risk: str
    requires: list[str] = Field(default_factory=list)
    reversible: bool = False


class AssistantUiDirectiveDTO(BaseModel):
    """前端待执行的 ui 指令(导航/筛选/开面板)。"""

    tool: str
    label: str
    args: dict = Field(default_factory=dict)


class AssistantProposedActionDTO(BaseModel):
    """写操作的待确认提案(可编辑卡片;确认走 /assistant/confirm,默认不执行)。"""

    tool: str
    label: str
    risk: str
    args: dict = Field(default_factory=dict)
    requires: list[str] = Field(default_factory=list)
    note: str = ""
    action_token: str = ""  # 防篡改令牌,确认时回传
    reversible: bool = False  # 执行后能否一键撤销
    before: dict = Field(default_factory=dict)  # 改动字段的当前值(before→after 差异)


class AssistantApprovalRequestDTO(BaseModel):
    """需管理员审批的「待发起申请」(闸判 APPROVE 时产出;不自动落工单)。

    助手当面提示操作员「需审批,是否发起?」,由人点「发起申请」(/assistant/request-approval)
    才真正进实时事件·待审批。stage:input=可疑输入待审 / output=回复待人工复核。
    """

    stage: str
    title: str
    reason: str
    risk_level: str
    excerpt: str = ""
    score: float = 0.0


class AssistantStepDTO(BaseModel):
    """一步执行轨迹(透明展示助手调了什么)。"""

    tool: str
    kind: str
    label: str
    ok: bool
    detail: str = ""


class AssistantChatResponse(BaseModel):
    session_id: str
    reply: str
    blocked: bool = False
    compressed: bool = False  # 本轮是否触发上下文自动压缩
    ui_directives: list[AssistantUiDirectiveDTO] = Field(default_factory=list)
    proposed_actions: list[AssistantProposedActionDTO] = Field(default_factory=list)
    approval_requests: list[AssistantApprovalRequestDTO] = Field(default_factory=list)
    steps: list[AssistantStepDTO] = Field(default_factory=list)


class AssistantRequestApprovalRequest(BaseModel):
    """操作员在对话里「发起审批申请」:把某条 APPROVE 判定落成真·待审批工单。"""

    session_id: str | None = Field(default=None, max_length=128)
    stage: str = Field(default="output", max_length=16)  # input | output
    reason: str = Field(default="", max_length=400)
    risk_level: str = Field(default="medium", max_length=16)
    excerpt: str = Field(default="", max_length=400)
    score: float = 0.0


class AssistantRequestApprovalResponse(BaseModel):
    ok: bool = True


class AssistantConfirmRequest(BaseModel):
    action_token: str = Field(min_length=1, max_length=4096)
    edited_args: dict = Field(default_factory=dict)
    session_id: str | None = Field(default=None, max_length=128)


class AssistantConfirmResponse(BaseModel):
    ok: bool
    summary: str
    action_id: str | None = None
    reversible: bool = False
    undo_preview: str = ""
    error: str | None = None


class ToolCallProposalRequest(ToolCallRequest):
    """控制台工具页创建待确认调用的请求；最终参数仍由 /assistant/confirm 复校。"""

    session_id: str | None = Field(default=None, max_length=128)


class AssistantUndoRequest(BaseModel):
    action_id: str = Field(min_length=1, max_length=128)
    session_id: str | None = Field(default=None, max_length=128)


class AssistantUndoResponse(BaseModel):
    ok: bool
    summary: str
    error: str | None = None


class AssistantModelConfigDTO(BaseModel):
    """回前端的模型接入配置(密钥掩码,只暴露是否已设置 / 是否配置完成)。"""

    protocol: str
    endpoint: str
    model: str
    api_key_masked: str
    api_key_set: bool
    timeout_seconds: float
    verify_tls: bool
    configured: bool
    ready: bool


class AssistantModelConfigUpdate(BaseModel):
    """保存模型接入配置。api_key 语义:None=保持原值;""=清空;非空=设新值(防掩码覆盖真值)。"""

    protocol: Literal["openai", "ollama", "anthropic"]
    endpoint: str = Field(max_length=512)
    model: str = Field(max_length=128)
    api_key: str | None = Field(default=None, max_length=2048)
    timeout_seconds: float = Field(default=90.0, ge=1, le=600)
    verify_tls: bool = True


class AssistantModelTestRequest(BaseModel):
    """测试连接:用「待保存的表单值」试调一次(api_key=None 时用已存密钥)。"""

    protocol: Literal["openai", "ollama", "anthropic"]
    endpoint: str = Field(max_length=512)
    model: str = Field(max_length=128)
    api_key: str | None = Field(default=None, max_length=2048)
    timeout_seconds: float = Field(default=30.0, ge=1, le=600)
    verify_tls: bool = True


class AssistantModelTestResponse(BaseModel):
    ok: bool
    detail: str
    latency_ms: int | None = None
