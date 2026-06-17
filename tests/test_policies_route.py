"""策略中心只读端点:把当前装配的 YAML 策略文档映射成可展示策略集。

验证策略页接真的后端契约:管线策略引擎暴露的文档被忠实映射(条件归一、处置/等级/理由保留),
且 pipeline.policy 访问器拿到的就是装配进管线的那个引擎。
"""

from __future__ import annotations

from fulcrum.adapters.api.policies_routes import to_policy_set
from fulcrum.app import build_pipeline
from fulcrum.capabilities.policy.yaml_policy import YamlPolicyEngine


def test_to_policy_set_maps_default_policy() -> None:
    engine = YamlPolicyEngine("data/policies/default.yml")
    ps = to_policy_set(engine.policy_document())

    assert ps.default == "allow"
    assert ps.version >= 1
    assert ps.workspace  # 受控工作区根
    assert "gov.cn" in ps.allow_domains
    assert len(ps.rules) == len(engine.policy_document().get("rules", []))

    by_id = {r.id: r for r in ps.rules}
    # 已知规则:任务链外泄 → block / critical,条件 chain_risk_at_least=0.8
    exfil = by_id["block-exfil-chain"]
    assert exfil.decision == "block"
    assert exfil.risk_level == "critical"
    assert [(c.key, c.value) for c in exfil.when] == [("chain_risk_at_least", "0.8")]
    assert exfil.reason


def test_value_formatting_list_and_bool() -> None:
    """列表条件 → 逗号串、布尔 → true/false(对齐前端 chip 展示)。"""
    doc = {
        "rules": [
            {
                "id": "r1",
                "when": {"tool_in": ["file.read", "file.write"], "path_sensitive": True},
                "decision": "block",
                "risk_level": "critical",
                "reason": "x",
            }
        ]
    }
    ps = to_policy_set(doc)
    cond = {c.key: c.value for c in ps.rules[0].when}
    assert cond["tool_in"] == "file.read, file.write"
    assert cond["path_sensitive"] == "true"


def test_pipeline_exposes_assembled_policy_engine() -> None:
    """pipeline.policy 即装配进管线的策略引擎,且能列出策略文档。"""
    pipe = build_pipeline()
    get_doc = getattr(pipe.policy, "policy_document", None)
    assert callable(get_doc)
    ps = to_policy_set(get_doc())
    assert ps.rules  # 默认装配的 yaml 策略非空
