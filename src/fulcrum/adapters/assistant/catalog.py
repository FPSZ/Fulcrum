"""AI 操作助手 · 动作目录(Action Catalog)。

每个可被助手调用的动作声明:`id`/`label`(给人看)/`description`(给 LLM 看的语义)/
`risk`(分级:只读·一般·高危)/`requires`(所需权限点,与 RBAC 同一套)/`args_hint`(参数说明)。

MVP 后端内置一份**只读导航/筛选**目录 + 一条**高危示例**(停用策略),开箱即可端到端跑;
前端落地时由 FeatureModule 注册同构动作并经请求体覆盖/扩展(见 doc 05 §1.2)。动作 id 与前端
handler 约定,后端只负责"选哪个动作 + 是否准许",不执行 UI 操作。
"""

from __future__ import annotations

from dataclasses import dataclass

# 风险分级:只读/导航可自动执行;一般需留意;高危(改策略/配置/成员等)必须二次确认。
RISK_READ_ONLY = "read_only"
RISK_NORMAL = "normal"
RISK_HIGH = "high"
RISK_LEVELS = (RISK_READ_ONLY, RISK_NORMAL, RISK_HIGH)


@dataclass(frozen=True, slots=True)
class Action:
    id: str
    label: str
    description: str
    risk: str
    requires: tuple[str, ...] = ()
    args_hint: str = ""


# 内置默认目录。requires 用真实权限点(adapters/auth/permissions.py),助手只能调当前角色能点的动作。
DEFAULT_CATALOG: tuple[Action, ...] = (
    Action(
        "nav.overview",
        "打开安全总览",
        "导航到安全总览页(KPI + 实时事件概览)",
        RISK_READ_ONLY,
        ("overview.view",),
    ),
    Action(
        "nav.events",
        "打开实时事件",
        "导航到实时事件页(逐条安全事件与证据链)",
        RISK_READ_ONLY,
        ("events.view",),
    ),
    Action(
        "nav.policies",
        "打开策略中心",
        "导航到策略中心页(当前装配的策略规则)",
        RISK_READ_ONLY,
        ("policies.view",),
    ),
    Action(
        "nav.audit",
        "打开审计溯源",
        "导航到审计溯源页(会话 hash-chain)",
        RISK_READ_ONLY,
        ("audit.view",),
    ),
    Action("nav.supply", "打开供应链", "导航到供应链组件扫描页", RISK_READ_ONLY, ("supply.view",)),
    Action("nav.tools", "打开工具网关", "导航到工具调用治理页", RISK_READ_ONLY, ("tools.view",)),
    Action(
        "filter.events",
        "筛选实时事件",
        "在实时事件页按处置或严重度筛选",
        RISK_READ_ONLY,
        ("events.view",),
        'args 如 {"disposition":"block|approve|allow","level":"low|medium|high|critical"},均可选',
    ),
    Action(
        "policy.disable",
        "停用策略",
        "临时停用一条安全策略规则(高危:会削弱防护,必须二次确认)",
        RISK_HIGH,
        ("policies.manage",),
        'args 形如 {"policy_id": "POL-014"}',
    ),
)
