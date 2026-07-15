"""供应链离线静态评测:样例索引、指标和 CLI 报告契约。"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from fulcrum.eval.__main__ import main as eval_main
from fulcrum.eval.supplychain import (
    SupplychainEvalResult,
    compute_supplychain_metrics,
    load_supplychain_dataset,
    run_supplychain_dataset,
)

_DATASET = "samples/supplychain/eval.json"


def _run_suite_module():
    path = Path("samples/eval/benchmarks/run_suite.py")
    spec = importlib.util.spec_from_file_location("run_suite", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_supplychain_static_samples_scan_with_evidence() -> None:
    samples = load_supplychain_dataset(_DATASET)
    results = run_supplychain_dataset(samples, _DATASET)

    assert len(results) == 3
    assert all(result.predicted_action == result.expected_action for result in results)
    assert all(result.evidence for result in results if result.malicious)
    metrics = compute_supplychain_metrics(results)
    assert metrics["scope"] == "offline_static_scan"
    assert metrics["recall"] == 1.0
    assert metrics["fpr"] == 0.0
    assert metrics["disposition_accuracy"] == 1.0


def test_supplychain_metrics_count_false_positive_and_disposition_mismatch() -> None:
    results = [
        SupplychainEvalResult(
            sample_id="mal",
            manifest="mal.yml",
            malicious=True,
            expected_action="block",
            predicted_action="allow",
        ),
        SupplychainEvalResult(
            sample_id="ben",
            manifest="ben.yml",
            malicious=False,
            expected_action="allow",
            predicted_action="approve",
        ),
    ]
    metrics = compute_supplychain_metrics(results)
    assert metrics["totals"] == {
        "samples": 2,
        "malicious": 1,
        "benign": 1,
        "tp": 0,
        "fn": 1,
        "fp": 1,
        "tn": 0,
    }
    assert metrics["recall"] == 0.0
    assert metrics["fpr"] == 1.0
    assert metrics["disposition_accuracy"] == 0.0


def test_eval_cli_writes_supplychain_static_report(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    assert (
        eval_main(["--dataset", "samples/eval/heldout/benign-heldout.jsonl", "--out", str(out)])
        == 0
    )

    report = json.loads(out.read_text(encoding="utf-8"))
    supplychain = report["supplychain_static"]
    assert supplychain["scope"] == "offline_static_scan"
    assert supplychain["metrics"]["recall"] == 1.0
    assert supplychain["metrics"]["fpr"] == 0.0
    assert any(sample["evidence"] for sample in supplychain["samples"] if sample["malicious"])


def test_regression_matrix_uses_static_supplychain_metrics() -> None:
    suite = _run_suite_module()
    metrics = {
        "asr_baseline": 1.0,
        "asr_fulcrum": 0.0,
        "asr_reduction": 1.0,
        "recall_bsr": 1.0,
        "precision": 1.0,
        "f1": 1.0,
        "fpr": 0.0,
        "utility": 1.0,
        "decision_accuracy": 1.0,
        "high_risk_handling": 1.0,
        "audit_complete_rate": 1.0,
        "hash_chain_pass_rate": 1.0,
        "source_traced_count": 0,
        "source_hit_at_1": 0.0,
        "source_hit_at_3": 0.0,
        "p95_latency_ms": 0.0,
        "by_gate": {},
        "supplychain_recall": 0.0,
        "supplychain_static": {"recall": 1.0, "fpr": 0.0, "disposition_accuracy": 1.0},
    }

    row = next(row for row in suite._p0_rows(metrics) if row[0].startswith("供应链静态组件"))
    assert row[1] == "100.0%" and row[3] == "✓"
    assert "100.0%" in suite._g4_rows(metrics)[2][1]
