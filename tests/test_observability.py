"""HTTP 请求关联与结构化日志的可观测性回归。"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

from fastapi.testclient import TestClient

from fulcrum.app import create_app
from fulcrum.config import Settings


def _client(tmp_path: Path) -> TestClient:
    settings = Settings(
        auth_db_path=str(tmp_path / "auth.sqlite"),
        bootstrap_admin_password="observability-admin-pw",
        gateway_config_path=str(tmp_path / "gateway.json"),
        audit_db_path=str(tmp_path / "audit.sqlite"),
        frontend_dir="",
    )
    return TestClient(create_app(settings))


def test_healthz_propagates_safe_correlation_ids(tmp_path: Path) -> None:
    response = _client(tmp_path).get(
        "/healthz",
        headers={"x-request-id": "req-20260731-001", "x-trace-id": "trace.demo:001"},
    )

    assert response.headers["x-request-id"] == "req-20260731-001"
    assert response.headers["x-trace-id"] == "trace.demo:001"


def test_healthz_replaces_untrusted_correlation_ids(tmp_path: Path) -> None:
    response = _client(tmp_path).get(
        "/healthz",
        headers={"x-request-id": "contains spaces", "x-trace-id": "x" * 129},
    )

    assert re.fullmatch(r"[0-9a-f]{32}", response.headers["x-request-id"])
    assert re.fullmatch(r"[0-9a-f]{32}", response.headers["x-trace-id"])


def test_body_limit_early_response_keeps_correlation_ids(tmp_path: Path) -> None:
    response = _client(tmp_path).get(
        "/healthz",
        headers={
            "content-length": "invalid",
            "x-request-id": "req-body-limit",
            "x-trace-id": "trace-body-limit",
        },
    )

    assert response.status_code == 400
    assert response.headers["x-request-id"] == "req-body-limit"
    assert response.headers["x-trace-id"] == "trace-body-limit"


def test_logging_emits_allowlisted_json_with_bound_context() -> None:
    script = """
from fulcrum.observability import bind_log_context, configure_logging, get_logger

configure_logging("INFO")
with bind_log_context(request_id="req-1", trace_id="trace-1"):
    get_logger("fulcrum.test").info(
        "http.request.completed",
        extra={
            "http_method": "GET",
            "http_path": "/healthz",
            "status_code": 200,
            "duration_ms": 1.25,
            "authorization": "Bearer must-not-appear",
        },
    )
"""
    env = os.environ.copy()
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        check=False,
        text=True,
        encoding="utf-8",
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stderr.strip().splitlines()[-1])
    assert payload["event"] == "http.request.completed"
    assert payload["request_id"] == "req-1"
    assert payload["trace_id"] == "trace-1"
    assert payload["http_method"] == "GET"
    assert payload["http_path"] == "/healthz"
    assert payload["status_code"] == 200
    assert payload["duration_ms"] == 1.25
    assert "must-not-appear" not in completed.stderr
