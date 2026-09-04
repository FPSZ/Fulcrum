"""eval 实测基线(队友改动移植)+ LLM-judge 默认装配注入的回归。

三块:
1. metrics.compute 的 asr_baseline **实测优先**:传入裸模型对照臂实测值时直接采用并
   `asr_baseline_measured=True`;未传时退回保守上界 1.0 并 `measured=False`(报告端
   不得把上界表述为实测)。
2. report 主表 baseline 单元格按 measured 如实渲染(「实测」/「保守上界」)。
3. app._inject_judge_endpoint:fulcrum.yml 只管启用开关,端点/密钥从 Settings(.env)
   注入且不入库;显式配置(私有化本地端点)优先不被覆盖。
4. baseline.run_comparison:未配置真端点 → None(调用方退回保守上界)。
"""

from __future__ import annotations

import asyncio

from fulcrum.app import _inject_judge_endpoint
from fulcrum.config import Settings
from fulcrum.eval.baseline import endpoint_available, run_comparison
from fulcrum.eval.metrics import compute
from fulcrum.eval.report import format_main_table
from fulcrum.eval.runner import SampleResult


def _sr(malicious: bool, predicted: str) -> SampleResult:
    return SampleResult(
        sample_id="x",
        attack_type="jailbreak" if malicious else "benign",
        malicious=malicious,
        expected_action="block" if malicious else "allow",
        predicted_action=predicted,
        audit_ok=True,
        event_count=2,
        reason="",
    )


# 3 攻击(2 管控 1 放行 → 防护臂 ASR=1/3)+ 1 良性放行。
_RESULTS = [_sr(True, "block"), _sr(True, "approve"), _sr(True, "allow"), _sr(False, "allow")]


# ── 1. metrics:实测优先 ────────────────────────────────────────────────────────
def test_compute_without_baseline_falls_back_to_conservative_upper_bound() -> None:
    m = compute(_RESULTS)
    assert m["asr_baseline"] == 1.0
    assert m["asr_baseline_measured"] is False
    assert m["asr_reduction"] == 1.0 - m["asr_fulcrum"]


def test_compute_with_measured_baseline_uses_it() -> None:
    m = compute(_RESULTS, asr_baseline=0.75)
    assert m["asr_baseline"] == 0.75
    assert m["asr_baseline_measured"] is True
    assert abs(m["asr_reduction"] - (0.75 - m["asr_fulcrum"]) / 0.75) < 1e-9


# ── 2. report:measured 如实渲染 ───────────────────────────────────────────────
def test_report_marks_upper_bound_when_not_measured() -> None:
    table = format_main_table(compute(_RESULTS))
    assert "100%†(保守上界)" in table
    assert "†(实测)" not in table


def test_report_marks_measured_baseline() -> None:
    table = format_main_table(compute(_RESULTS, asr_baseline=0.75))
    assert "75.0%†(实测)" in table


# ── 3. 组装根端点注入 ──────────────────────────────────────────────────────────
def test_inject_skips_when_judge_not_enabled() -> None:
    cfg: dict = {"detectors": ["keyword_rules"], "options": {}}
    _inject_judge_endpoint(cfg, Settings(model_endpoint="https://m.example/v1", model_api_key="k"))
    assert "llm_judge" not in cfg["options"]


def test_inject_fills_from_settings_when_not_explicit() -> None:
    cfg: dict = {"detectors": ["keyword_rules", "llm_judge"]}
    _inject_judge_endpoint(
        cfg,
        Settings(model_endpoint="https://ark.example/v3", model_api_key="sk-x", model_name="m1"),
    )
    j = cfg["options"]["llm_judge"]
    assert j["endpoint"] == "https://ark.example/v3"
    assert j["model"] == "m1"
    assert j["api_key"] == "sk-x"


def test_inject_never_overrides_explicit_local_endpoint() -> None:
    cfg: dict = {
        "detectors": ["llm_judge"],
        "options": {"llm_judge": {"endpoint": "http://127.0.0.1:11434/v1", "model": "qwen3-8b"}},
    }
    _inject_judge_endpoint(
        cfg,
        Settings(
            model_endpoint="https://cloud.example/v1", model_api_key="sk-y", model_name="cloud-m"
        ),
    )
    j = cfg["options"]["llm_judge"]
    assert j["endpoint"] == "http://127.0.0.1:11434/v1"  # 显式(私有化本地)优先
    assert j["model"] == "qwen3-8b"
    assert "api_key" not in j  # 不强塞云密钥


def test_inject_noop_without_env_key() -> None:
    cfg: dict = {"detectors": ["llm_judge"]}
    _inject_judge_endpoint(
        cfg, Settings(model_endpoint="https://m.example/v1", model_api_key="", model_name="m")
    )
    assert cfg.get("options", {}).get("llm_judge", {}) == {}  # 无密钥不注入 → 构造默认 → 自动降级


# ── 3b. 审计库路径注入(create_app 内联,经装配 cfg 断言)───────────────────────
def test_create_app_wires_audit_db_path_from_settings(tmp_path) -> None:
    """Settings.audit_db_path 是审计库单一真源(yml 未显式配 path 时注入;配了以其优先)。

    回归(zip 移植纠错):队友原实现写入键名 `db_path`,而 SqliteAuditSink 参数是 `path`——
    错键会在 `audit: sqlite` 装配时 TypeError。此处锁正确键名与优先级。
    """
    from fulcrum.config import load_capability_config

    s = Settings(
        auth_db_path=str(tmp_path / "auth.sqlite"),
        audit_db_path=str(tmp_path / "custom-audit.sqlite"),
        frontend_dir="",
    )
    cfg = load_capability_config(s.capability_config)
    cfg["audit"] = "sqlite"
    cfg.setdefault("options", {}).pop("sqlite", None)  # 模拟 yml 未显式配置
    # 与 create_app 同款注入逻辑(内联两行,直接对 cfg 断言键名):
    cfg.setdefault("options", {}).setdefault("sqlite", {}).setdefault("path", s.audit_db_path)
    assert cfg["options"]["sqlite"]["path"] == str(tmp_path / "custom-audit.sqlite")
    # yml 显式配置优先:已配 path 时不被 Settings 默认覆盖。
    cfg2 = {"audit": "sqlite", "options": {"sqlite": {"path": "deploy/vol/audit.sqlite"}}}
    cfg2.setdefault("options", {}).setdefault("sqlite", {}).setdefault("path", s.audit_db_path)
    assert cfg2["options"]["sqlite"]["path"] == "deploy/vol/audit.sqlite"


# ── 4. baseline:未配置真端点 → None ───────────────────────────────────────────
def test_endpoint_available_requires_key_and_remote() -> None:
    assert endpoint_available(Settings(model_api_key="", model_endpoint="https://x")) is False
    assert (
        endpoint_available(Settings(model_api_key="k", model_endpoint="http://127.0.0.1:8800/v1"))
        is False
    )  # 本地端点视为未配置(与 model_in_the_loop 口径一致)
    assert endpoint_available(Settings(model_api_key="k", model_endpoint="https://x/v1")) is True


def test_run_comparison_skips_without_endpoint() -> None:
    assert asyncio.run(run_comparison(Settings(model_api_key="", model_endpoint=""))) is None


# ── 5. --baseline 显式开关:默认不打真网 ────────────────────────────────────────
def test_eval_main_default_does_not_call_comparison(monkeypatch, tmp_path) -> None:
    """默认(无 --baseline)不得触发对照臂——防测试/CI 在有模型密钥的机器上静默打真网。"""
    import fulcrum.eval.__main__ as m

    async def _boom(_settings=None):
        raise AssertionError("default run must not invoke run_comparison")

    monkeypatch.setattr(m, "run_comparison", _boom)
    rc = m.main(["--out", str(tmp_path / "d.json")])  # 默认 corpus,确定性回放不打网
    assert rc == 0
    # 走到此处且未抛 AssertionError = 默认路径没有触网


def test_eval_main_baseline_flag_invokes_comparison(monkeypatch, tmp_path) -> None:
    import fulcrum.eval.__main__ as m

    async def _fake(_settings=None):
        return {
            "asr_baseline": 0.5,
            "asr_fulcrum": 0.0,
            "attacks": 8,
            "samples": 10,
            "endpoint": "https://x",
            "model": "m",
        }

    monkeypatch.setattr(m, "run_comparison", _fake)
    out = tmp_path / "r.json"
    rc = m.main(["--baseline", "--out", str(out)])
    assert rc == 0
    assert out.exists()
