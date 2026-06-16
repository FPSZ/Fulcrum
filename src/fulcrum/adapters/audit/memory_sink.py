"""InMemoryAuditSink —— append-only + **版本化** hash-chain 审计。

event_hash = sha256(prev_hash + canonical(event))。canonical 是事件的**冻结证据表示**:
只覆盖白名单字段(`_HASHED_FIELDS`),与 pydantic 模型的演进**解耦**——日后给 AuditEvent
增字段不会改变历史事件的 canonical,因而不破坏既有链的可验证性。要把新字段纳入哈希
保护,必须显式 bump `AuditEvent.schema_version` 并在此处分支新的字段集 + 迁移既有链。

verify 用事件**写入当时的 schema_version** 重算,而非"拿今天的模型重算昨天的事件"——
这是把"防篡改证据链"做成真正可冻结地基的关键(否则任何审计字段演进都会一笔勾销历史)。

M1+ 落 SQLite/PostgreSQL append-only 表时,持久化 schema_version 与各 *_hash;接口不变。
"""

from __future__ import annotations

import hashlib
import json

from ...core.domain import AuditEvent
from ...core.errors import AuditError
from ...core.registry import capability

_GENESIS = "GENESIS"

# 各 schema_version 下"受哈希保护"的字段集(event_hash 自身永远除外)。
# 顺序无关(canonical 用 sort_keys)。改动某版本的集合 = 改哈希口径,禁止;
# 需要变更时新增一个版本号条目,并为既有链提供迁移。
_HASHED_FIELDS: dict[int, frozenset[str]] = {
    1: frozenset(
        {
            "schema_version",
            "event_id",
            "session_id",
            "event_type",
            "subject_id",
            "decision",
            "evidence",
            "index",
            "prev_hash",
        }
    ),
}


def _canonical(event: AuditEvent) -> str:
    """事件的冻结规范表示(用于哈希)。仅含该 schema_version 白名单内的字段。"""
    fields = _HASHED_FIELDS.get(event.schema_version)
    if fields is None:
        raise AuditError(f"未知审计 schema_version={event.schema_version},无法计算/校验哈希链")
    payload = event.model_dump(mode="json", include=set(fields))
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _event_hash(event: AuditEvent) -> str:
    return hashlib.sha256((event.prev_hash + _canonical(event)).encode("utf-8")).hexdigest()


@capability("audit", "memory")
class InMemoryAuditSink:
    def __init__(self) -> None:
        self._chains: dict[str, list[AuditEvent]] = {}

    def append(self, event: AuditEvent) -> AuditEvent:
        chain = self._chains.setdefault(event.session_id, [])
        event.index = len(chain)
        event.prev_hash = chain[-1].event_hash if chain else _GENESIS
        event.event_hash = _event_hash(event)  # 未知版本 → AuditError 直接上抛(写入不可降级)
        chain.append(event)
        return event

    def events(self, session_id: str) -> list[AuditEvent]:
        return list(self._chains.get(session_id, []))

    def verify_chain(self, session_id: str) -> bool:
        prev = _GENESIS
        for event in self._chains.get(session_id, []):
            try:
                expected = _event_hash(event)
            except AuditError:
                return False  # 未知格式视为不可验证(fail-closed),不抛错给查询端
            if event.prev_hash != prev or event.event_hash != expected:
                return False
            prev = event.event_hash
        return True
