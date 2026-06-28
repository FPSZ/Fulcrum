"""审计 hash-chain:正常校验通过,篡改后校验失败,canonical 与模型演进解耦。"""

from __future__ import annotations

import asyncio
import json

from fulcrum.adapters.audit.hashchain import _HASHED_FIELDS, canonical
from fulcrum.adapters.audit.memory_sink import InMemoryAuditSink
from fulcrum.core.domain import AuditEvent, AuditEventType


def _sink_with_events(n: int) -> InMemoryAuditSink:
    sink = InMemoryAuditSink()

    async def _build() -> None:
        for _ in range(n):
            await sink.append(
                AuditEvent(session_id="s", event_type=AuditEventType.REQUEST_RECEIVED)
            )

    asyncio.run(_build())
    return sink


def test_chain_verifies() -> None:
    sink = _sink_with_events(3)
    assert asyncio.run(sink.verify_chain("s")) is True
    events = asyncio.run(sink.events("s"))
    assert events[0].prev_hash == "GENESIS"
    assert events[1].prev_hash == events[0].event_hash


def test_tamper_detected() -> None:
    sink = _sink_with_events(3)
    asyncio.run(sink.events("s"))[1].evidence = {"tampered": True}
    assert asyncio.run(sink.verify_chain("s")) is False


def test_events_carry_schema_version() -> None:
    sink = _sink_with_events(1)
    assert asyncio.run(sink.events("s"))[0].schema_version == 1


def test_canonical_only_covers_whitelisted_fields() -> None:
    """冻结契约:canonical 只含白名单字段。日后给 AuditEvent 加字段不得改变哈希口径——
    若有人误把新字段纳入(或改用全量 model_dump),此断言立即失败。"""
    ev = AuditEvent(session_id="s", event_type=AuditEventType.REQUEST_RECEIVED)
    keys = set(json.loads(canonical(ev)).keys())
    assert keys == set(_HASHED_FIELDS[ev.schema_version])
    assert "event_hash" not in keys  # event_hash 永不参与自身哈希


def test_unknown_schema_version_fails_verification() -> None:
    """未知 schema_version(格式损坏/越级写入)→ 视为不可验证,fail-closed 返回 False。"""
    sink = _sink_with_events(2)
    asyncio.run(sink.events("s"))[1].schema_version = 99
    assert asyncio.run(sink.verify_chain("s")) is False


def test_locate_break_pinpoints_tampered_index() -> None:
    """取证:篡改第 2 条(下标 1)→ locate_break 精确返回 1,而非只给布尔。"""
    sink = _sink_with_events(4)
    asyncio.run(sink.events("s"))[1].evidence = {"tampered": True}
    assert asyncio.run(sink.locate_break("s")) == 1


def test_locate_break_none_when_intact() -> None:
    sink = _sink_with_events(3)
    assert asyncio.run(sink.locate_break("s")) is None


def test_hmac_changes_event_hash() -> None:
    """配了封缄密钥 → event_hash 走 HMAC,与裸 SHA256 不同(口径切换)。"""
    from fulcrum.adapters.audit import hashchain

    ev = AuditEvent(session_id="s", event_type=AuditEventType.REQUEST_RECEIVED)
    ev.prev_hash = "GENESIS"
    try:
        hashchain.configure_hmac_key(None)
        plain = hashchain.event_hash(ev)
        hashchain.configure_hmac_key("audit-secret-key")
        keyed = hashchain.event_hash(ev)
        assert plain != keyed
    finally:
        hashchain.configure_hmac_key(None)


def test_hmac_chain_blocks_keyless_forgery() -> None:
    """启用 HMAC 后,拿到库写权限但无密钥的攻击者无法伪造合法链:

    攻击者改一条证据并用「公开算法 + 创世」重算其后全部哈希——但没有密钥只能算裸 SHA256;
    取证端用真密钥校验立即识破。这正是裸链(可被内部人重写)补不上的那一刀。
    """
    from fulcrum.adapters.audit import hashchain

    try:
        hashchain.configure_hmac_key("audit-secret-key")
        sink = _sink_with_events(3)  # 在 HMAC 口径下封缄
        assert asyncio.run(sink.verify_chain("s")) is True

        events = asyncio.run(sink.events("s"))
        events[1].evidence = {"tampered": True}
        # 模拟攻击者:无密钥,只能裸 SHA256 重算被改事件及其后链
        hashchain.configure_hmac_key(None)
        prev = events[0].event_hash
        for ev in events[1:]:
            ev.prev_hash = prev
            ev.event_hash = hashchain.event_hash(ev)
            prev = ev.event_hash

        # 取证端用真密钥校验 → 识破伪造
        hashchain.configure_hmac_key("audit-secret-key")
        assert asyncio.run(sink.verify_chain("s")) is False
    finally:
        hashchain.configure_hmac_key(None)
    assert asyncio.run(sink.locate_break("no-such-session")) is None


def test_locate_break_reports_first_of_multiple_tampers() -> None:
    """多处被改 → 返回最靠前的位置(链在首处断裂即失去可验证性)。"""
    sink = _sink_with_events(5)
    events = asyncio.run(sink.events("s"))
    events[3].evidence = {"t": 3}
    events[2].evidence = {"t": 2}
    assert asyncio.run(sink.locate_break("s")) == 2


def test_locate_break_flags_unknown_schema_position() -> None:
    sink = _sink_with_events(3)
    asyncio.run(sink.events("s"))[2].schema_version = 99
    assert asyncio.run(sink.locate_break("s")) == 2
