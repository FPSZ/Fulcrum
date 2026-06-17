"""策略中心路由 —— 只读暴露管线**当前装配的**声明式 YAML 策略,经 policies.view 鉴权。

策略页要回答「现在到底按什么规则在判」。本端点取运行管线的策略引擎文档(条件→分级处置,
自上而下首条命中),映射成可展示的策略集。改策略仍只改 data/policies/*.yml,本端点只读不写。
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from fastapi import Depends, FastAPI

from ..auth import Principal
from .deps import AuthDeps
from .schemas import PolicyConditionDTO, PolicyRuleDTO, PolicySetDTO

if TYPE_CHECKING:
    from ...core.pipeline import SecurityPipeline


def _fmt_value(value: Any) -> str:
    """把 when 条件值归一为展示串:列表→逗号连接、布尔→true/false、其余→str。"""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    return str(value)


def to_policy_set(doc: dict[str, Any]) -> PolicySetDTO:
    """把策略文档(YamlPolicyEngine 加载的 dict)映射成策略集 DTO(纯函数,便于测试)。"""
    rules = [
        PolicyRuleDTO(
            id=str(rule.get("id", "")),
            when=[
                PolicyConditionDTO(key=k, value=_fmt_value(v))
                for k, v in (rule.get("when") or {}).items()
            ],
            decision=str(rule.get("decision", "")),
            risk_level=str(rule.get("risk_level", "")),
            reason=str(rule.get("reason", "")),
        )
        for rule in doc.get("rules", [])
    ]
    return PolicySetDTO(
        name=str(doc.get("name") or "枢衡安全策略"),
        version=int(doc.get("version", 1)),
        default=str(doc.get("default", "allow")),
        workspace=str(doc.get("workspace", "")),
        allow_domains=[str(d) for d in doc.get("allow_domains", [])],
        rules=rules,
    )


def register_policies_routes(app: FastAPI, pipeline: SecurityPipeline, deps: AuthDeps) -> None:
    can_view = deps.require("policies.view")

    @app.get("/policies", response_model=PolicySetDTO | None)
    async def policies(_: Principal = Depends(can_view)) -> PolicySetDTO | None:
        # 鸭子类型而非 isinstance:adapters 不依赖 capabilities(import-linter 边界)。
        # 声明式策略引擎暴露 policy_document();其它实现(如 allow_all)无,则无文档可列。
        get_doc = getattr(pipeline.policy, "policy_document", None)
        if not callable(get_doc):
            return None
        return to_policy_set(cast("dict[str, Any]", get_doc()))
