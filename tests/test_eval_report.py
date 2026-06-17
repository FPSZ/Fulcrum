"""评测报告只读端点:读最近一次 `python -m fulcrum.eval` 产物;缺失/损坏诚实当作「尚无报告」。"""

from __future__ import annotations

import json
from pathlib import Path

from fulcrum.adapters.api.eval_routes import load_report


def test_loads_committed_latest_report() -> None:
    """仓库内 docs/eval/results/latest.json 应能被解析为合法报告。"""
    report = load_report("docs/eval/results/latest.json")
    assert report is not None
    assert report.dataset
    assert report.metrics.totals.samples == len(report.samples)
    assert 0.0 <= report.metrics.asr_fulcrum <= 1.0
    assert all(s.sample_id for s in report.samples)


def test_missing_file_returns_none(tmp_path: Path) -> None:
    assert load_report(tmp_path / "nope.json") is None


def test_malformed_json_returns_none(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{ not valid json", encoding="utf-8")
    assert load_report(bad) is None


def test_schema_mismatch_returns_none(tmp_path: Path) -> None:
    """结构不符(缺 dataset/metrics)视为尚无报告,不抛错。"""
    wrong = tmp_path / "wrong.json"
    wrong.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")
    assert load_report(wrong) is None
