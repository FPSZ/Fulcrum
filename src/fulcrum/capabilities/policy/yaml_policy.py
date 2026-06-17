"""YamlPolicyEngine —— 声明式 YAML 策略引擎,对应赛题目标①②。

把"来源信任 / 工具 / 风险等级 / 路径 / 域名 / 命令 / 归因置信度"等条件,映射到分级处置
(allow / sanitize / approve / block)。规则自上而下,**首条命中即决定**;否则 default 兜底。
策略与代码分离:调策略只改 `data/policies/default.yml`,核心代码零改动。

信任级条件有两种:`source_trust` 精确匹配某一级;`source_trust_at_least` 做序比较——
按**不信任程度**(trusted<semi_trusted<untrusted)匹配"至少这么不可信"的来源,与
`risk_at_least` 同向(门槛越高越严)。前者写不出"半可信或更糟"这类区间,后者一句即可。

未知条件键 / 拼错的信任级在加载期即报错(fail-closed),避免被静默忽略导致"看似生效实则放行"。
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import yaml

from ...core.domain import Context, Disposition, PolicyDecision, RiskLevel, ToolIntent, TrustLevel
from ...core.errors import ConfigError
from ...core.registry import capability
from ..toolguard import argrisk

_DEFAULT_POLICY = Path("data/policies/default.yml")

# 允许出现在 rule.when 里的条件键(白名单,拼错即报错)。
_PREDICATES = frozenset(
    {
        "tool_in",
        "tool_name",
        "source_trust",
        "source_trust_at_least",
        "risk_at_least",
        "attribution_at_least",
        "chain_risk_at_least",
        "risk_level",
        "path_sensitive",
        "path_outside_workspace",
        "domain_allowed",
        "command_dangerous",
    }
)
_BOOL_FACTS = frozenset(
    {"path_sensitive", "path_outside_workspace", "domain_allowed", "command_dangerous"}
)
# 信任级按**不信任程度**升序排名:trusted 最低、untrusted 最高。`source_trust_at_least`
# 据此做"至少这么不可信"的序比较(语义与 risk_at_least 同向:数值/排名越高=风险越大)。
_TRUST_RANK: dict[TrustLevel, int] = {
    TrustLevel.TRUSTED: 0,
    TrustLevel.SEMI_TRUSTED: 1,
    TrustLevel.UNTRUSTED: 2,
}
_TRUST_RANK_BY_VALUE: dict[str, int] = {lvl.value: rank for lvl, rank in _TRUST_RANK.items()}
# 接受信任级字面量的条件键(加载期校验取值合法,拼错的级别 fail-closed 报错而非静默不匹配)。
_TRUST_PREDICATES = frozenset({"source_trust", "source_trust_at_least"})


def _risk_level(score: float) -> RiskLevel:
    if score >= 0.8:
        return RiskLevel.CRITICAL
    if score >= 0.6:
        return RiskLevel.HIGH
    if score >= 0.4:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


@capability("policy", "yaml")
class YamlPolicyEngine:
    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path) if path else _DEFAULT_POLICY
        self._policy = self._load(self._path)

    @staticmethod
    def _load(path: Path) -> dict[str, Any]:
        if not path.exists():
            raise ConfigError(f"策略文件不存在:{path}")
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for rule in data.get("rules", []):
            when = rule.get("when", {})
            unknown = set(when) - _PREDICATES
            if unknown:
                raise ConfigError(f"策略规则 {rule.get('id')!r} 含未知条件:{sorted(unknown)}")
            for key in _TRUST_PREDICATES & set(when):
                if when[key] not in _TRUST_RANK_BY_VALUE:
                    raise ConfigError(
                        f"策略规则 {rule.get('id')!r} 的 {key} 含未知信任级:{when[key]!r}"
                        f"(可选:{sorted(_TRUST_RANK_BY_VALUE)})"
                    )
        return data

    def policy_document(self) -> dict[str, Any]:
        """当前装配的策略文档(深拷贝,只读展示用 —— 调用方改不动内部状态)。"""
        return copy.deepcopy(self._policy)

    async def decide(self, intent: ToolIntent, ctx: Context) -> PolicyDecision:
        facts = self._facts(intent, ctx)
        for rule in self._policy.get("rules", []):
            if self._matches(rule.get("when", {}), facts):
                level = (
                    RiskLevel(rule["risk_level"]) if "risk_level" in rule else facts["risk_level"]
                )
                return PolicyDecision(
                    decision=Disposition(rule["decision"]),
                    reason=rule.get("reason", ""),
                    matched_policy_id=rule.get("id"),
                    risk_level=level,
                )
        return PolicyDecision(
            decision=Disposition(self._policy.get("default", "allow")),
            reason="未命中任何规则,按默认处置",
            matched_policy_id=None,
            risk_level=facts["risk_level"],
        )

    # ---- 事实装配:把 intent + ctx 归一成可匹配的扁平事实 ----
    def _facts(self, intent: ToolIntent, ctx: Context) -> dict[str, Any]:
        args = intent.arguments
        workspace = str(self._policy.get("workspace", "data/workspace"))
        allow_domains = list(self._policy.get("allow_domains", []))
        return {
            "tool": intent.tool_name,
            "risk_score": intent.risk_score,
            "risk_level": _risk_level(intent.risk_score),
            "attribution_confidence": intent.attribution_confidence,
            "chain_risk": self._chain_risk(intent, ctx),
            "source_trust": self._worst_trust(intent, ctx),
            "path_sensitive": argrisk.path_sensitive(args),
            "path_outside_workspace": argrisk.path_outside_workspace(args, workspace),
            "domain_allowed": argrisk.domain_allowed(args, allow_domains),
            "command_dangerous": argrisk.command_dangerous(args),
        }

    @staticmethod
    def _chain_risk(intent: ToolIntent, ctx: Context) -> float:
        """当前调用的任务链风险 = 由本次调用触发的链 finding(chain.*)的最高分。

        按 evidence.intent_id 过滤,确保只对"当前这步"判链,不被会话中其它步的链 finding 误伤。
        """
        return max(
            (
                f.score
                for f in ctx.findings
                if f.kind.startswith("chain.") and f.evidence.get("intent_id") == intent.intent_id
            ),
            default=0.0,
        )

    @staticmethod
    def _worst_trust(intent: ToolIntent, ctx: Context) -> str | None:
        by_id = {s.source_id: s for s in ctx.spans}
        trusts = [by_id[sid].trust_level for sid in intent.derived_from_sources if sid in by_id]
        if trusts:
            return max(trusts, key=lambda t: _TRUST_RANK[t]).value
        # 有声明来源却无 span 可核验(工具网关路径)→ fail-closed 视为不可信。
        if intent.derived_from_sources:
            return TrustLevel.UNTRUSTED.value
        return None

    def _matches(self, when: dict[str, Any], facts: dict[str, Any]) -> bool:
        return all(self._check(key, expected, facts) for key, expected in when.items())

    @staticmethod
    def _check(key: str, expected: Any, facts: dict[str, Any]) -> bool:
        if key == "tool_in":
            return facts["tool"] in expected
        if key == "tool_name":
            return facts["tool"] == expected
        if key == "source_trust":
            return facts["source_trust"] == expected
        if key == "source_trust_at_least":
            actual = facts["source_trust"]
            if actual is None:  # 无来源(直连用户)→ 不满足任何"至少这么不可信"门槛
                return False
            return _TRUST_RANK_BY_VALUE[str(actual)] >= _TRUST_RANK_BY_VALUE[str(expected)]
        if key == "risk_at_least":
            return facts["risk_score"] >= float(expected)
        if key == "attribution_at_least":
            return facts["attribution_confidence"] >= float(expected)
        if key == "chain_risk_at_least":
            return facts["chain_risk"] >= float(expected)
        if key == "risk_level":
            return facts["risk_level"].value == expected
        if key in _BOOL_FACTS:
            return facts[key] is bool(expected)
        return False  # 不可达:未知键已在加载期拦下
