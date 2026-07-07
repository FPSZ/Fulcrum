"""SqliteAuditSink —— append-only hash-chain 审计的**持久化**落库实现。

与 `InMemoryAuditSink` 接口逐方法对齐(append/events/verify_chain/locate_break/session_ids/
all_events/prune_to_recent),哈希链口径共用 `hashchain` 模块 → 同一批事件在内存桩与本
落库实现下算出**完全一致**的链,可互验。区别只在"存哪":重启不清零、有历史、跨进程可查。

落库要点:
- 一行一事件,`body` 存整条 `AuditEvent` 的 JSON(全保真,查询时 `model_validate` 复原),
  另把 hash-chain 关键字段(session_id/idx/prev_hash/event_hash/created_at/...)拆成索引列。
- **append 在一次 `BEGIN IMMEDIATE` 事务内**算链尾 → 盖戳 → 落库:并发追加同一会话时,
  写锁串行化,index/prev_hash 不会因竞态错位(内存桩单线程隐式串行,落库须显式)。
- schema 迁移走共享 `sqlite_support`(PRAGMA user_version);加变更=追加更高 version 迁移。
- 每操作开短连接(WAL,开销极小),不跨线程共享连接——与 SQLiteAuthStore 同款取舍。
"""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path

from ...core.domain import AuditEvent
from ...core.registry import capability
from ..sqlite_support import Migration, connect, run_migrations
from .hashchain import GENESIS, event_hash, locate_break

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
    row_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id     TEXT    NOT NULL,
    idx            INTEGER NOT NULL,
    event_id       TEXT    NOT NULL,
    event_type     TEXT    NOT NULL,
    subject_id     TEXT,
    decision       TEXT,
    schema_version INTEGER NOT NULL,
    prev_hash      TEXT    NOT NULL,
    event_hash     TEXT    NOT NULL,
    created_at     REAL    NOT NULL,
    body           TEXT    NOT NULL,
    UNIQUE(session_id, idx)
);
CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_events(session_id, idx);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at);
"""


def _migrate_v1(conn: sqlite3.Connection) -> None:
    conn.executescript(_SCHEMA)


_MIGRATIONS = (Migration(1, _migrate_v1),)


@capability("audit", "sqlite")
class SqliteAuditSink:
    def __init__(self, path: str = "data/runtime/fulcrum.sqlite") -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with connect(self._path) as conn:
            run_migrations(conn, _MIGRATIONS)

    # ── 写入 ──────────────────────────────────────────────────────
    async def append(self, event: AuditEvent) -> AuditEvent:
        """在一次写事务内算链尾 → 盖戳 → 落库(并发追加同一会话由写锁串行化)。

        同步 sqlite 经 `asyncio.to_thread` 卸载 —— 落库不阻塞事件循环(M14):
        审计写在每次判定的 await 路径上,阻塞即拖慢全部并发请求。
        """
        return await asyncio.to_thread(self._append_sync, event)

    def _append_sync(self, event: AuditEvent) -> AuditEvent:
        with connect(self._path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT idx, event_hash FROM audit_events "
                    "WHERE session_id = ? ORDER BY idx DESC LIMIT 1",
                    (event.session_id,),
                ).fetchone()
                event.index = (int(row["idx"]) + 1) if row else 0
                event.prev_hash = row["event_hash"] if row else GENESIS
                event.event_hash = event_hash(event)  # 未知版本 → AuditError 上抛,事务回滚
                conn.execute(
                    "INSERT INTO audit_events(session_id, idx, event_id, event_type, subject_id, "
                    "decision, schema_version, prev_hash, event_hash, created_at, body) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        event.session_id,
                        event.index,
                        event.event_id,
                        event.event_type.value,
                        event.subject_id,
                        event.decision.value if event.decision else None,
                        event.schema_version,
                        event.prev_hash,
                        event.event_hash,
                        event.created_at,
                        event.model_dump_json(),
                    ),
                )
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        return event

    # ── per-session 读 ────────────────────────────────────────────
    async def events(self, session_id: str) -> list[AuditEvent]:
        """读取 + JSON 反序列化经 to_thread 卸载,长链读取不阻塞事件循环(M14)。"""
        return await asyncio.to_thread(self._events_sync, session_id)

    def _events_sync(self, session_id: str) -> list[AuditEvent]:
        with connect(self._path) as conn:
            rows = conn.execute(
                "SELECT body FROM audit_events WHERE session_id = ? ORDER BY idx",
                (session_id,),
            ).fetchall()
        return [AuditEvent.model_validate_json(r["body"]) for r in rows]

    async def verify_chain(self, session_id: str) -> bool:
        """全链重算校验(读+哈希都在工作线程)。**不缓存结果**:校验的意义正是发现
        落库后被篡改的留痕,缓存布尔值会把事后篡改掩盖到进程重启——防篡改语义优先。
        """
        return await asyncio.to_thread(self._locate_break_sync, session_id) is None

    async def locate_break(self, session_id: str) -> int | None:
        """定位会话链首处断裂位置(防篡改取证);完好返回 None。逻辑见 hashchain。"""
        return await asyncio.to_thread(self._locate_break_sync, session_id)

    def _locate_break_sync(self, session_id: str) -> int | None:
        return locate_break(self._events_sync(session_id))

    # ── 跨会话聚合读(端口契约;供总览/事件/工具/审计列表)──────────────
    def session_ids(self) -> list[str]:
        """全部会话 id,按各会话首次出现的写入序(MIN(row_id))升序 —— 与内存桩"插入序"对齐。

        用 row_id 而非 created_at:同批快速写入时间戳可能相等,row_id 严格单调,排序确定。
        """
        with connect(self._path) as conn:
            rows = conn.execute(
                "SELECT session_id FROM audit_events GROUP BY session_id ORDER BY MIN(row_id)"
            ).fetchall()
        return [r["session_id"] for r in rows]

    def all_events(self) -> list[AuditEvent]:
        """全量事件,按写入序(row_id)排列 —— 与事件发生顺序一致;调用方多会再按时间重排。"""
        with connect(self._path) as conn:
            rows = conn.execute("SELECT body FROM audit_events ORDER BY row_id").fetchall()
        return [AuditEvent.model_validate_json(r["body"]) for r in rows]

    def prune_to_recent(self, max_sessions: int) -> None:
        """限长:仅保留最近活动的 max_sessions 个会话,删更早的(供长跑实时流量控库体积)。

        "最近活动"按各会话最后一行的 `row_id`(自增,严格单调的写入序)排序——而非 created_at:
        同批快速写入的 created_at 可能相等,row_id 永不并列,故限窗结果确定、与内存桩插入序一致。
        """
        with connect(self._path) as conn:
            stale = conn.execute(
                "SELECT session_id FROM audit_events GROUP BY session_id "
                "ORDER BY MAX(row_id) DESC LIMIT -1 OFFSET ?",
                (max_sessions,),
            ).fetchall()
            if stale:
                conn.executemany(
                    "DELETE FROM audit_events WHERE session_id = ?",
                    [(r["session_id"],) for r in stale],
                )
