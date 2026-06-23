"""AI 操作助手(后端大脑)—— 自然语言意图 → 受治理的控制台动作规划。

详见 doc 05 §1。本包只做"选哪个动作 + 是否准许"(RBAC/风险/审计),不执行 UI 操作。
"""

from __future__ import annotations

from .actuator import (
    ActionTokenSigner,
    AssistantActuator,
    ConfirmResult,
    UndoResult,
    UndoStore,
)
from .agent import (
    AssistantAgent,
    AssistantProposedAction,
    AssistantRunResult,
    AssistantStep,
    AssistantUiDirective,
)
from .catalog import DEFAULT_CATALOG, RISK_LEVELS, Action
from .conversation import ConversationStore, Summarizer
from .model_client import (
    ModelReply,
    ModelTurn,
    StreamChunk,
    StreamTurn,
    make_dynamic_model_backend,
    make_dynamic_stream_backend,
    to_function_spec,
)
from .planner import AssistantPlan, make_model_backend, plan
from .services import AssistantServices

__all__ = [
    "DEFAULT_CATALOG",
    "RISK_LEVELS",
    "Action",
    "ActionTokenSigner",
    "AssistantActuator",
    "AssistantAgent",
    "AssistantPlan",
    "AssistantProposedAction",
    "AssistantRunResult",
    "AssistantServices",
    "AssistantStep",
    "AssistantUiDirective",
    "ConfirmResult",
    "ConversationStore",
    "ModelReply",
    "ModelTurn",
    "StreamChunk",
    "StreamTurn",
    "Summarizer",
    "UndoResult",
    "UndoStore",
    "make_dynamic_model_backend",
    "make_dynamic_stream_backend",
    "make_model_backend",
    "plan",
    "to_function_spec",
]
