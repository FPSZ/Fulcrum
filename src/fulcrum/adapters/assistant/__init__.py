"""AI 操作助手(后端大脑)—— 自然语言意图 → 受治理的控制台动作规划。

详见 doc 05 §1。本包只做"选哪个动作 + 是否准许"(RBAC/风险/审计),不执行 UI 操作。
"""

from __future__ import annotations

from .catalog import DEFAULT_CATALOG, RISK_LEVELS, Action
from .planner import AssistantPlan, make_model_backend, plan

__all__ = [
    "DEFAULT_CATALOG",
    "RISK_LEVELS",
    "Action",
    "AssistantPlan",
    "make_model_backend",
    "plan",
]
