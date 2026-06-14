"""InMemoryAuditSink —— M0 审计实现:进程内 append-only + hash-chain。

event_hash = sha256(prev_hash + canonical_json(event 去掉 event_hash))。
M1+ 替换为 SQLite/PostgreSQL append-only 表(接口不变)。
"""

from __future__ import annotations

import hashlib
import json

from ...core.domain import AuditEvent
from ...core.registry import capability

_GENESIS = "GENESIS"


def _canonical(event: AuditEvent) -> str:
    payload = event.model_dump(mode="json", exclude={"event_hash"})
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


@capability("audit", "memory")
class InMemoryAuditSink:
    def __init__(self) -> None:
        self._chains: dict[str, list[AuditEvent]] = {}

    def append(self, event: AuditEvent) -> AuditEvent:
        chain = self._chains.setdefault(event.session_id, [])
        event.index = len(chain)
        event.prev_hash = chain[-1].event_hash if chain else _GENESIS
        event.event_hash = hashlib.sha256(
            (event.prev_hash + _canonical(event)).encode("utf-8")
        ).hexdigest()
        chain.append(event)
        return event

    def events(self, session_id: str) -> list[AuditEvent]:
        return list(self._chains.get(session_id, []))

    def verify_chain(self, session_id: str) -> bool:
        prev = _GENESIS
        for event in self._chains.get(session_id, []):
            if event.prev_hash != prev:
                return False
            expected = hashlib.sha256(
                (event.prev_hash + _canonical(event)).encode("utf-8")
            ).hexdigest()
            if event.event_hash != expected:
                return False
            prev = event.event_hash
        return True
