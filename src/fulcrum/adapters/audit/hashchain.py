"""审计 hash-chain 共享原语 —— **所有** AuditSink 实现的单一哈希真源。

内存桩与 SQLite 持久化两套 sink 必须用**完全一致**的 canonical / event_hash 口径,
否则同一批事件在两种 sink 下算出不同链、互不可验证。故把"冻结证据表示 + 链封缄 + 断点
定位"抽到此处,memory_sink 与 sqlite_sink 一并复用,杜绝两处哈希实现漂移。

event_hash = sha256(prev_hash + canonical(event))。canonical 是事件的**冻结证据表示**:
只覆盖白名单字段(`_HASHED_FIELDS`),与 pydantic 模型的演进**解耦**——日后给 AuditEvent
增字段不会改变历史事件的 canonical,因而不破坏既有链的可验证性。要把新字段纳入哈希
保护,必须显式 bump `AuditEvent.schema_version` 并在此处分支新的字段集 + 迁移既有链。

verify 用事件**写入当时的 schema_version** 重算,而非"拿今天的模型重算昨天的事件"——
这是把"防篡改证据链"做成真正可冻结地基的关键(否则任何审计字段演进都会一笔勾销历史)。
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Iterable

from ...core.domain import AuditEvent
from ...core.errors import AuditError

GENESIS = "GENESIS"

# 链封缄密钥(可选,经 .env 的 FULCRUM_AUDIT_HMAC_KEY 注入,启动时 configure_hmac_key 设入)。
# 设了 → event_hash 走 HMAC-SHA256:拿到库写权限的攻击者**没有密钥就无法伪造合法链**
# (改一条事件后重算其后全部哈希也对不上)。留空(默认)→ 退回裸 SHA256,保持既有行为与可验证性。
# 注:切换密钥/启停会改变哈希口径,既有链需在同一口径下校验;故仅在部署初始化时设定一次。
_HMAC_KEY: bytes | None = None


def configure_hmac_key(key: str | None) -> None:
    """设置审计链封缄密钥(进程级,启动时调用一次)。空/None = 不启用 HMAC(裸 SHA256)。"""
    global _HMAC_KEY
    _HMAC_KEY = key.encode("utf-8") if key else None

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


def canonical(event: AuditEvent) -> str:
    """事件的冻结规范表示(用于哈希)。仅含该 schema_version 白名单内的字段。"""
    fields = _HASHED_FIELDS.get(event.schema_version)
    if fields is None:
        raise AuditError(f"未知审计 schema_version={event.schema_version},无法计算/校验哈希链")
    payload = event.model_dump(mode="json", include=set(fields))
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def event_hash(event: AuditEvent) -> str:
    data = (event.prev_hash + canonical(event)).encode("utf-8")
    if _HMAC_KEY is not None:
        return hmac.new(_HMAC_KEY, data, hashlib.sha256).hexdigest()
    return hashlib.sha256(data).hexdigest()


def seal(event: AuditEvent, *, index: int, prev_hash: str) -> AuditEvent:
    """把链位置盖戳到事件并算出 event_hash(append 时落库前调用)。

    index/prev_hash 由 sink 据"该会话已有链"算出(内存数链、SQLite 查链),口径一致;
    未知 schema_version → AuditError 直接上抛(写入不可降级,fail-closed)。
    """
    event.index = index
    event.prev_hash = prev_hash
    event.event_hash = event_hash(event)
    return event


def locate_break(events: Iterable[AuditEvent]) -> int | None:
    """定位审计链中第一处断裂的事件**位置下标**(防篡改取证)。

    断裂判据:`prev_hash` 未接上前件、`event_hash` 与重算值不符、或 `schema_version` 未知
    (无法验证 → fail-closed 视为断裂)。链完好返回 None。下标用链内实际位置(enumerate),
    不取事件自带的 `index` 字段——后者本身可能正是被篡改项。
    """
    prev = GENESIS
    for pos, event in enumerate(events):
        try:
            expected = event_hash(event)
        except AuditError:
            return pos  # 未知格式视为不可验证(fail-closed),不抛错给查询端
        if event.prev_hash != prev or event.event_hash != expected:
            return pos
        prev = event.event_hash
    return None
