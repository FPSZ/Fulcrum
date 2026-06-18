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

    # async:与 AuditSink 端口一致(内存桩无真实 IO,故体内无 await;SQLite 实现将有)。
    async def append(self, event: AuditEvent) -> AuditEvent:
        chain = self._chains.setdefault(event.session_id, [])
        event.index = len(chain)
        event.prev_hash = chain[-1].event_hash if chain else _GENESIS
        event.event_hash = _event_hash(event)  # 未知版本 → AuditError 直接上抛(写入不可降级)
        chain.append(event)
        return event

    async def events(self, session_id: str) -> list[AuditEvent]:
        return list(self._chains.get(session_id, []))

    # ── 聚合读取(供总览统计端点跨会话汇总)──────────────────────────
    # 端口 AuditSink 只暴露 per-session 读;这两个是内存实现的具体扩展,调用方
    # 按 isinstance 窄化使用(见 demo/runtime 同款先例)。SQLite 实现将以一条
    # 聚合查询提供等价能力,不必逐链拉全量。
    def session_ids(self) -> list[str]:
        return list(self._chains.keys())

    def all_events(self) -> list[AuditEvent]:
        return [event for chain in self._chains.values() for event in chain]

    async def verify_chain(self, session_id: str) -> bool:
        return await self.locate_break(session_id) is None

    async def locate_break(self, session_id: str) -> int | None:
        """定位审计链中第一处断裂的事件**位置下标**(防篡改取证)。

        断裂判据与 `verify_chain` 同源:`prev_hash` 未接上前件、`event_hash` 与重算值不符、
        或 `schema_version` 未知(无法验证 → fail-closed 视为断裂)。链完好返回 None。
        相对只给布尔的 `verify_chain`,这里指出**哪一条**被篡改/缺失,供审计溯源页与取证
        精确定位。下标用链内实际位置(enumerate),不取事件自带的 index 字段——后者本身
        可能正是被篡改项。
        """
        prev = _GENESIS
        for pos, event in enumerate(self._chains.get(session_id, [])):
            try:
                expected = _event_hash(event)
            except AuditError:
                return pos  # 未知格式视为不可验证(fail-closed),不抛错给查询端
            if event.prev_hash != prev or event.event_hash != expected:
                return pos
            prev = event.event_hash
        return None
