"""控制台「发起评测」(POST /eval/run)—— 组装层 EvalRunner + 端点 + 鉴权。

钉死:① EvalRunner 跑一次写出 JSON + md 报告并返回 dict;② 空报告实例 POST /eval/run 后
GET /eval/report 即非空(在控制台触发出分,不依赖 CLI);③ 发起评测需 `eval.run`(仅 view → 403);
④ 未装配 runner → 409;⑤ run 完 running 复位、CLI 与控制台共用同一出分函数(产物口径一致)。
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi.testclient import TestClient

from fulcrum.adapters.api import build_api
from fulcrum.adapters.api.eval_routes import load_report
from fulcrum.adapters.auth import build_auth_bundle
from fulcrum.app import build_pipeline
from fulcrum.config import Settings, load_capability_config
from fulcrum.eval_runner import EvalRunner

_ADMIN_PW = "eval-admin-pw"
_LOW_PW = "eval-low-pw"
_DATASET = "samples/eval/chains.jsonl"  # 小集,测试快
_POLICY = "data/policies/gov_demo.yml"


# ----------------------------- 组装层 runner -----------------------------


def test_eval_runner_writes_report_and_returns_dict(tmp_path: Path) -> None:
    out = tmp_path / "latest.json"
    runner = EvalRunner(str(out), _DATASET, _POLICY)
    assert runner.running is False

    report = asyncio.run(runner.run())

    assert isinstance(report, dict) and "metrics" in report
    assert out.is_file() and out.with_suffix(".md").is_file()  # JSON + md 记分卡都落了
    assert load_report(out) is not None  # 产物能被读路径校验通过
    assert runner.running is False  # 跑完锁释放


# ----------------------------- HTTP 端到端 -----------------------------


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        auth_db_path=str(tmp_path / "auth.sqlite"),
        bootstrap_admin_password=_ADMIN_PW,
        gateway_config_path=str(tmp_path / "gateway.json"),
        console_settings_path=str(tmp_path / "console.json"),
        assistant_model_config_path=str(tmp_path / "model.json"),
        conversation_dir=str(tmp_path / "conv"),
        eval_report_path=str(tmp_path / "latest.json"),
        eval_dataset=_DATASET,
        eval_policy=_POLICY,
        audit_db_path=str(tmp_path / "audit.sqlite"),
        frontend_dir="",
    )


def _build(settings: Settings, with_runner: bool = True):
    bundle = build_auth_bundle(settings)
    pipeline = build_pipeline(load_capability_config(settings.capability_config))
    runner = (
        EvalRunner(settings.eval_report_path, settings.eval_dataset, settings.eval_policy)
        if with_runner
        else None
    )
    return TestClient(build_api(pipeline, bundle, settings, eval_runner=runner)), bundle


def _login(client: TestClient, user: str, pw: str) -> None:
    assert client.post("/auth/login", json={"username": user, "password": pw}).status_code == 200


def test_run_eval_populates_report_from_empty(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    client, _ = _build(settings)
    _login(client, "admin", _ADMIN_PW)

    assert client.get("/eval/report").json() is None  # 还没跑过 → 空态
    resp = client.post("/eval/run")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body is not None and body["metrics"]["totals"]["samples"] >= 1
    # 落盘且 GET 也读到了(控制台触发出分闭环)
    assert Path(settings.eval_report_path).is_file()
    assert client.get("/eval/report").json() is not None


def test_run_eval_requires_run_permission(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    client, bundle = _build(settings)
    role = bundle.directory.create_role("仅看评测", "", ["eval.view"])
    bundle.directory.create_user(
        username="low",
        display_name="低权",
        role_id=role.id,
        department_id=None,
        password=_LOW_PW,
    )
    _login(client, "low", _LOW_PW)

    assert client.get("/eval/report").status_code == 200  # 有 view
    assert client.post("/eval/run").status_code == 403  # 缺 eval.run


def test_run_eval_without_runner_returns_409(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    client, _ = _build(settings, with_runner=False)
    _login(client, "admin", _ADMIN_PW)
    assert client.post("/eval/run").status_code == 409
