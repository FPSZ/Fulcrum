"""LLM-judge 准入基准的纯函数回归，不调用模型端点。"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


def _bench_module():
    path = Path("samples/eval/benchmarks/llm_judge_bench.py")
    spec = importlib.util.spec_from_file_location("llm_judge_bench", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_latency_percentiles_use_linear_interpolation() -> None:
    bench = _bench_module()
    values = [0.1, 0.2, 0.3, 0.4, 0.5]

    assert bench._percentile_ms(values, 50) == 300.0
    assert bench._percentile_ms(values, 95) == 480.0
    assert bench._percentile_ms(values, 99) == 496.0
    assert bench._percentile_ms([], 95) is None


def test_latency_percentile_rejects_invalid_percentile() -> None:
    bench = _bench_module()

    with pytest.raises(ValueError, match="percentile"):
        bench._percentile_ms([0.1], 101)


def test_admission_requires_clean_heldout_and_latency() -> None:
    bench = _bench_module()

    eligible, reasons = bench._admission(
        heldout_fpr=0.02,
        heldout_samples=31,
        latency_p95_ms=800.0,
        failures=0,
        degraded_calls=0,
    )

    assert eligible is True
    assert reasons == []


def test_admission_reports_each_rejection_reason() -> None:
    bench = _bench_module()

    eligible, reasons = bench._admission(
        heldout_fpr=0.11,
        heldout_samples=31,
        latency_p95_ms=5_001.0,
        failures=1,
        degraded_calls=2,
    )

    assert eligible is False
    assert len(reasons) == 4
    assert "held-out FPR" in reasons[0]
    assert "P95" in reasons[1]
    assert "后端失败" in reasons[2]
    assert "fail-safe" in reasons[3]


def test_warmup_counters_do_not_affect_admission_metrics() -> None:
    bench = _bench_module()

    counters = {"calls": 3, "failures": 1, "degraded_calls": 3}
    bench._reset_measurement_counters(counters)
    eligible, reasons = bench._admission(
        heldout_fpr=0.02,
        heldout_samples=31,
        latency_p95_ms=800.0,
        failures=counters["failures"],
        degraded_calls=counters["degraded_calls"],
    )

    assert eligible and reasons == []
