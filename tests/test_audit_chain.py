"""审计 hash-chain:正常校验通过,篡改后校验失败。"""

from __future__ import annotations

from fulcrum.adapters.audit.memory_sink import InMemoryAuditSink
from fulcrum.core.domain import AuditEvent, AuditEventType


def _sink_with_events(n: int) -> InMemoryAuditSink:
    sink = InMemoryAuditSink()
    for _ in range(n):
        sink.append(AuditEvent(session_id="s", event_type=AuditEventType.REQUEST_RECEIVED))
    return sink


def test_chain_verifies() -> None:
    sink = _sink_with_events(3)
    assert sink.verify_chain("s") is True
    events = sink.events("s")
    assert events[0].prev_hash == "GENESIS"
    assert events[1].prev_hash == events[0].event_hash


def test_tamper_detected() -> None:
    sink = _sink_with_events(3)
    sink.events("s")[1].evidence = {"tampered": True}
    assert sink.verify_chain("s") is False
