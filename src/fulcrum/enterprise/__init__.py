"""企业智能体(被保护方)—— 一个**无任何安全管控**的政务大厅智能体。

这是"我们网关之外、需要被保护的企业系统":它只管接用户消息、调真实大模型(MiMo)、
按模型意图执行业务工具,绝不自行判断安全。所有拦截/审核由前置的枢衡网关负责。

运行:  uv run python -m fulcrum.enterprise   (默认 http://127.0.0.1:8800)
"""

from __future__ import annotations

from .agent import EnterpriseAgent
from .server import create_enterprise_app

__all__ = ["EnterpriseAgent", "create_enterprise_app"]
