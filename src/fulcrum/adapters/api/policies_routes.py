"""策略中心路由 —— 读取并**编辑**管线当前装配的声明式 YAML 策略,经 policies.* 鉴权。

- ``GET /policies``(policies.view):取运行管线的策略引擎文档,映射成可展示的策略集。
- ``PUT /policies``(policies.manage):控制台编辑策略——调默认处置/工作区/外联白名单,
  逐规则启停/改处置/改理由/删除。**不开放裸 ``when`` 谓词编辑**(避免误配削弱防护):规则按
  id 合并回当前文档以保留其 ``when``/风险等级。校验通过即热生效(下次 ``decide`` 读新文档)、
  落盘持久化(``data/runtime/policy.yml``,重启不丢)、并写一条 ``POLICY_UPDATED`` 审计。

经 ``getattr`` 鸭子类型调策略引擎(``policy_document``/``replace_document``),不依赖 capabilities
具体类(import-linter:adapters↛capabilities 边界);非声明式引擎(如 allow_all)无这些方法 → 只读降级。
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from fastapi import Depends, FastAPI, HTTPException, status

from ...core.domain import AuditEvent, AuditEventType
from ..auth import Principal
from .deps import AuthDeps
from .schemas import PolicyConditionDTO, PolicyRuleDTO, PolicySetDTO, PolicySetWrite

if TYPE_CHECKING:
    from ...core.pipeline import SecurityPipeline
    from ..policy_store import PolicyDocStore


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
            enabled=rule.get("enabled") is not False,  # 缺省视为启用,仅显式 false 为停用
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


def merge_policy_edit(current: dict[str, Any], body: PolicySetWrite) -> dict[str, Any]:
    """把控制台编辑(顶层字段 + 规则补丁)合并回当前文档,产出新文档(纯函数,便于测试)。

    规则按 body.rules 的**顺序与全集**重建:逐条按 id 取回当前文档的原规则(保留其 ``when``/
    ``risk_level``)再覆盖 enabled/decision/reason;current 里不在 body 中的规则即被删除。
    未知 id(current 没有)跳过——前端提交的就是当前规则集,正常不会出现。版本号 +1。
    """
    by_id = {str(r.get("id")): r for r in current.get("rules", [])}
    new_rules: list[dict[str, Any]] = []
    for patch in body.rules:
        base = by_id.get(patch.id)
        if base is None:
            continue
        new_rules.append(
            {**base, "enabled": patch.enabled, "decision": patch.decision, "reason": patch.reason}
        )
    return {
        **current,
        "default": body.default,
        "workspace": body.workspace,
        "allow_domains": list(body.allow_domains),
        "rules": new_rules,
        "version": int(current.get("version", 1)) + 1,
    }


def register_policies_routes(
    app: FastAPI, pipeline: SecurityPipeline, store: PolicyDocStore, deps: AuthDeps
) -> None:
    can_view = deps.require("policies.view")
    can_manage = deps.require("policies.manage")  # 编辑策略是写操作,单独鉴权

    @app.get("/policies", response_model=PolicySetDTO | None)
    async def policies(_: Principal = Depends(can_view)) -> PolicySetDTO | None:
        # 鸭子类型而非 isinstance:adapters 不依赖 capabilities(import-linter 边界)。
        # 声明式策略引擎暴露 policy_document();其它实现(如 allow_all)无,则无文档可列。
        get_doc = getattr(pipeline.policy, "policy_document", None)
        if not callable(get_doc):
            return None
        return to_policy_set(cast("dict[str, Any]", get_doc()))

    @app.put("/policies", response_model=PolicySetDTO)
    async def update_policies(
        body: PolicySetWrite, principal: Principal = Depends(can_manage)
    ) -> PolicySetDTO:
        get_doc = getattr(pipeline.policy, "policy_document", None)
        replace = getattr(pipeline.policy, "replace_document", None)
        if not callable(get_doc) or not callable(replace):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail="当前策略引擎不支持在线编辑"
            )
        current = cast("dict[str, Any]", get_doc())
        new_doc = merge_policy_edit(current, body)
        # 校验先行:非法字段(未知谓词/非法处置/坏信任级)抛 ConfigError(FulcrumError)→ 自动 400,
        # 且**不会**替换掉正在生效的策略(fail-closed),也不落盘。校验过才热生效。
        replace(new_doc)
        store.save(new_doc)  # 落盘:重启后启动期重新应用(见 app.py)
        await pipeline.audit.append(
            AuditEvent(
                # 配置变更自成一链,不混入请求会话/事件墙(后者只投影 policy_decided)
                session_id="config:policy",
                event_type=AuditEventType.POLICY_UPDATED,
                subject_id=principal.username,
                evidence={
                    "actor": principal.username,
                    "version": new_doc.get("version"),
                    "default": new_doc.get("default"),
                    "rule_count": len(new_doc.get("rules", [])),
                    "disabled": [
                        str(r.get("id"))
                        for r in new_doc.get("rules", [])
                        if r.get("enabled") is False
                    ],
                    "allow_domains": list(new_doc.get("allow_domains", [])),
                },
            )
        )
        return to_policy_set(new_doc)
