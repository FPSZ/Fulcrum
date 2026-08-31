"""评测报告只读端点:读最近一次 `python -m fulcrum.eval` 产物;缺失/损坏诚实当作「尚无报告」。"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from fulcrum.adapters.api.eval_routes import load_report
from fulcrum.eval.__main__ import main as eval_main


def test_eval_cli_reconfigures_gbk_stdio_to_utf8(tmp_path: Path) -> None:
    """Windows 默认 GBK 管道也能完整输出含 `†` 的评测表,不触发 UnicodeEncodeError。"""
    dataset = tmp_path / "minimal.jsonl"
    dataset.write_text(
        json.dumps(
            {
                "sample_id": "windows-gbk",
                "attack_type": "benign",
                "input": "hello",
                "expected_action": "allow",
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "report.json"
    env = os.environ.copy()
    env["PYTHONUTF8"] = "0"
    env["PYTHONIOENCODING"] = "gbk"

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "fulcrum.eval",
            "--dataset",
            str(dataset),
            "--out",
            str(out),
        ],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
    assert "†".encode() in completed.stdout
    assert out.exists()


def test_loads_report_produced_by_eval_cli(tmp_path: Path) -> None:
    """端点消费的报告 = `python -m fulcrum.eval` 实际产出的报告(生产者→消费者契约)。

    不依赖 docs/eval/results/latest.json(该产物被 gitignore,全新检出不存在)——
    现场用 CLI 产一个再 load,保证两端 schema 始终一致。
    """
    out = tmp_path / "report.json"
    assert eval_main(["--out", str(out)]) == 0
    report = load_report(out)
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
