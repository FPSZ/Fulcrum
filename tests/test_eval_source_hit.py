"""溯源命中率@1/@3:工具级样例的来源归因评测([指标体系 §7.2] P0)。

归因器按「参数片段是否原文出现于来源 + 来源信任级」给候选打分排序,金标 source_id
落在候选前 k 名即命中。本测试用精心构造的归因样例集验证端到端命中,并单测命中率算法。
"""

from __future__ import annotations

import asyncio

from fulcrum.app import build_pipeline
from fulcrum.eval.__main__ import _EVAL_CONFIG
from fulcrum.eval.dataset import load_dataset
from fulcrum.eval.metrics import _source_hit, compute
from fulcrum.eval.runner import SampleResult, run_dataset, run_sample

_ATTR = "samples/eval/govoffice-attribution.jsonl"


def _pipeline():
    return build_pipeline(_EVAL_CONFIG)


def test_attribution_dataset_loads() -> None:
    samples = load_dataset(_ATTR)
    assert len(samples) == 4
    assert all(s.is_tool_sample and s.sources and s.expected_trace_source for s in samples)


def test_source_hit_perfect_on_curated_set() -> None:
    samples = load_dataset(_ATTR)
    results = asyncio.run(run_dataset(_pipeline(), samples))
    m = compute(results)
    assert m["source_attribution_samples"] == 4
    assert m["source_hit_at_1"] == 1.0
    assert m["source_hit_at_3"] == 1.0


def test_ranking_puts_untrusted_source_first() -> None:
    samples = {s.sample_id: s for s in load_dataset(_ATTR)}
    r = asyncio.run(run_sample(_pipeline(), samples["attr-rank"]))
    # 同一片段命中两条来源,更不可信的网页来源应排在候选首位。
    assert r.attributed_sources[0] == "web-page"
    assert "mem-note" in r.attributed_sources


# ---- 命中率算法单测(与管线解耦)----
def _mk(sid: str, gold: str | None, attr: list[str]) -> SampleResult:
    return SampleResult(
        sample_id=sid,
        attack_type="x",
        malicious=True,
        expected_action="block",
        predicted_action="block",
        expected_trace_source=gold,
        attributed_sources=attr,
    )


def test_source_hit_metric_math() -> None:
    rs = [
        _mk("a", "s1", ["s1", "s2"]),  # 命中@1
        _mk("b", "s3", ["s0", "s9", "s3"]),  # 命中@3,不@1
        _mk("c", "s5", ["s6", "s7"]),  # 未命中
        _mk("d", None, []),  # 无金标 → 不计入分母
    ]
    assert _source_hit(rs, 1) == 1 / 3
    assert _source_hit(rs, 3) == 2 / 3


def test_no_gold_yields_none() -> None:
    assert _source_hit([_mk("d", None, [])], 1) is None
    m = compute(
        [
            SampleResult(
                sample_id="x",
                attack_type="benign",
                malicious=False,
                expected_action="allow",
                predicted_action="allow",
            )
        ]
    )
    assert m["source_hit_at_1"] is None
    assert m["source_attribution_samples"] == 0
