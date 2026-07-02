"""来源信任级归约 —— 单一真源。

"本次工具调用所依据来源的最坏信任级(worst-first),无可核验来源则 None,有声明来源却无 span
可核验则 fail-closed 视为不可信" 这一判据,此前在 `core.pipeline`(审计富化)与
`capabilities.policy.yaml_policy`(策略判定)各写了一份,值一致但两处独立、易随改动漂移。
收敛到此处,二者共用,消除口径分裂(评审 M1)。
"""

from __future__ import annotations

from .domain import Context, ToolIntent, TrustLevel

# 信任级排序:worst-first(越靠前越不可信)。判"最坏信任级"的唯一顺序依据。
_WORST_FIRST: tuple[TrustLevel, ...] = (
    TrustLevel.UNTRUSTED,
    TrustLevel.SEMI_TRUSTED,
    TrustLevel.TRUSTED,
)


def intent_worst_trust(intent: ToolIntent, ctx: Context) -> str | None:
    """归因到的各来源 span 里最不可信的一档(worst-first);无可核验来源则 None。

    有声明来源却无 span 可核验(工具网关路径)→ 视为不可信(fail-closed)。返回 TrustLevel.value。
    """
    by_id = {s.source_id: s for s in ctx.spans}
    trusts = {by_id[sid].trust_level for sid in intent.derived_from_sources if sid in by_id}
    for level in _WORST_FIRST:
        if level in trusts:
            return level.value
    if intent.derived_from_sources:
        return TrustLevel.UNTRUSTED.value
    return None
