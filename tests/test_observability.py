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


# ── 评审 #126 补充:异常路径 / 恶意 correlation ID / 白名单与脱敏 / 请求原文不落日志 ──
def _run_script(script: str) -> tuple[str, str]:
    import subprocess  # noqa: F401  # 顶部已 import subprocess,此处保持局部可读

    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        check=False,
        text=True,
        encoding="utf-8",
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout, completed.stderr


def _last_log_json(stderr: str, event: str | None = None) -> dict:
    """取最后一条(或指定 event 的)JSON 日志行。

    注意 stderr 里可能混有第三方 logger(如 httpx 访问日志,其自身已把 query 打码)经同一
    formatter 输出的行——按 event 过滤才能稳定取到我们的中间件日志。
    """
    lines = [
        ln
        for ln in stderr.strip().splitlines()
        if ln.startswith("{") and (event is None or f'"event":"{event}"' in ln)
    ]
    assert lines, stderr
    return json.loads(lines[-1])


def test_exception_path_logged_sanitized_and_reraised() -> None:
    """异常路径:记 http.request.failed + exception_type,500 仍抛,异常消息里的敏感量不落日志。"""
    stdout, stderr = _run_script(
        """
from fastapi import FastAPI
from fastapi.testclient import TestClient
from fulcrum.observability import configure_logging
from fulcrum.observability.http import install_request_observability

configure_logging("INFO")
app = FastAPI()
install_request_observability(app)

@app.get("/boom")
async def boom():
    raise RuntimeError("内部错误,凭据 手机号13812345678 不外泄")

client = TestClient(app, raise_server_exceptions=False)
r = client.get("/boom", headers={"x-request-id": "req-exc-1"})
print("STATUS", r.status_code, r.headers.get("x-request-id"))
"""
    )
    assert "STATUS 500" in stdout
    payload = _last_log_json(stderr, "http.request.failed")
    assert payload["event"] == "http.request.failed"
    assert payload["exception_type"] == "RuntimeError"
    assert payload["status_code"] == 500
    assert payload["request_id"] == "req-exc-1"
    # 异常消息(含手机号)绝不进日志:只记异常类型,不带 traceback/消息。
    assert "13812345678" not in stderr
    # 注:500 响应本体由 Starlette 外层 ServerErrorMiddleware 生成(不经过本中间件),
    # 故错误响应不回显 x-request-id;失败请求的关联靠上面这条失败日志携带 request_id。


def test_malicious_correlation_id_replaced_no_log_forging() -> None:
    """恶意 correlation ID(JSON 注入/引号/反斜杠/超长混合)→ 替换为随机 hex,日志无伪造键。"""
    stdout, stderr = _run_script(
        """
from fastapi import FastAPI
from fastapi.testclient import TestClient
from fulcrum.observability import configure_logging
from fulcrum.observability.http import install_request_observability

configure_logging("INFO")
app = FastAPI()
install_request_observability(app)

@app.get("/ping")
async def ping():
    return {"ok": True}

client = TestClient(app)
evil = 'req-1\\"},\\"injected\\":\\"x'
r = client.get("/ping", headers={"x-request-id": evil, "x-trace-id": "t" * 200})
print("REQID", r.headers.get("x-request-id"))
"""
    )
    assert "REQID " in stdout
    reqid = stdout.split("REQID ", 1)[1].strip()
    assert re.fullmatch(r"[0-9a-f]{32}", reqid)
    # 每一行日志都是合法 JSON,没有注入出的 injected 键。
    for line in stderr.strip().splitlines():
        if line.startswith("{"):
            payload = json.loads(line)
            assert "injected" not in payload
            if "request_id" in payload:
                assert re.fullmatch(r"[0-9a-f]{32}", payload["request_id"])


def test_event_message_redacted_and_extra_fields_dropped() -> None:
    """消息正文过 redact(手机号/身份证打码),extra 里非白名单字段(api_key/原文)不落日志。"""
    _, stderr = _run_script(
        """
from fulcrum.observability import bind_log_context, configure_logging, get_logger

configure_logging("INFO")
with bind_log_context(session_id="sess-1", password="must-not-bind"):
    get_logger("fulcrum.test").info(
        "处理消息 手机号13812345678 身份证110101199003077777",
        extra={"api_key": "sk-must-not-appear", "user_input": "请求原文不落日志",
               "http_method": "POST"},
    )
"""
    )
    payload = _last_log_json(stderr)
    assert payload["session_id"] == "sess-1"
    assert "password" not in payload  # 非白名单上下文字段不绑定
    assert payload["http_method"] == "POST"
    assert "api_key" not in payload and "user_input" not in payload
    assert "13812345678" not in stderr and "110101199003077777" not in stderr
    assert "sk-must-not-appear" not in stderr and "请求原文不落日志" not in stderr
    assert "138****" in payload["event"]  # redact 打码后形态


def test_query_string_and_body_never_logged() -> None:
    """http_path 只落路由模板:query 里的令牌、请求体原文绝不进日志。"""
    stdout, stderr = _run_script(
        """
from fastapi import FastAPI
from fastapi.testclient import TestClient
from fulcrum.observability import configure_logging
from fulcrum.observability.http import install_request_observability

configure_logging("INFO")
app = FastAPI()
install_request_observability(app)

@app.get("/echo")
async def echo():
    return {"ok": True}

client = TestClient(app)
r = client.get("/echo?token=sk-live-secret123456")
print("PATH", r.headers.get("x-request-id") is not None)
"""
    )
    assert "PATH True" in stdout
    payload = _last_log_json(stderr, "http.request.completed")
    assert payload["http_path"] == "/echo"  # 路由模板,非原始 URL
    assert "sk-live-secret123456" not in stderr
    assert "token=sk" not in stderr
