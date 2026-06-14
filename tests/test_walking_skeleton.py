"""Walking Skeleton 端到端:空管线跑通 + 审计链可校验。"""

from __future__ import annotations

from fastapi.testclient import TestClient

from fulcrum.app import create_app


def _client() -> TestClient:
    return TestClient(create_app())


def test_healthz() -> None:
    resp = _client().get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_chat_completions_runs_pipeline_and_audits() -> None:
    client = _client()
    resp = client.post(
        "/v1/chat/completions",
        json={"session_id": "s1", "messages": [{"role": "user", "content": "hello"}]},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["session_id"] == "s1"
    # FakeModelClient 产出一个 echo 工具调用,allow_all 放行并执行
    assert "echo" in body["tool_calls"]
    assert body["outcomes"][0]["decision"] == "allow"
    assert body["outcomes"][0]["executed"] is True

    # 审计链存在且校验通过(hash-chain)
    audit = client.get("/audit/s1").json()
    assert audit["verified"] is True
    assert len(audit["events"]) > 0


def test_tools_call_executes_echo() -> None:
    client = _client()
    resp = client.post(
        "/tools/call",
        json={"session_id": "s2", "tool_name": "echo", "arguments": {"text": "hi"}},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "allow"
    assert body["executed"] is True
    assert body["output"] == "hi"
