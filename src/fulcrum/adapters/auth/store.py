"""SQLite 用户/会话库 —— 鉴权的持久化端口。

设计取舍:
- 每次操作开一条短连接(WAL 持久、开销极小);避免跨线程共享连接(FastAPI 同步路由跑在线程池)。
- 会话存的是令牌的 SHA-256,而非令牌本身 —— 即便库被读走,也拿不到可用令牌(单向)。
- 时间戳一律 UTC 纪元秒(整数),由上层注入,store 不自取时钟,便于测试与审计对齐。
- 失败计数与锁定窗口落库,使暴力破解防护跨进程重启仍生效。
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .models import User

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    display_name  TEXT    NOT NULL,
    password_hash TEXT    NOT NULL,
    is_active     INTEGER NOT NULL DEFAULT 1,
    failed_count  INTEGER NOT NULL DEFAULT 0,
    lockout_until INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT    PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
"""


class SQLiteAuthStore:
    def __init__(self, db_path: str) -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self._path, isolation_level=None)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            yield conn
        finally:
            conn.close()

    def _ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    # ── 用户 ──────────────────────────────────────────────────────
    def count_users(self) -> int:
        with self._connect() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM users").fetchone()[0])

    def create_user(
        self, username: str, display_name: str, password_hash: str, now: int
    ) -> User:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO users(username, display_name, password_hash, created_at) "
                "VALUES(?,?,?,?)",
                (username, display_name, password_hash, now),
            )
            uid = int(cur.lastrowid or 0)
        return User(uid, username, display_name, password_hash, True)

    def get_user(self, username: str) -> User | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, username, display_name, password_hash, is_active "
                "FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        if row is None:
            return None
        return User(
            row["id"], row["username"], row["display_name"],
            row["password_hash"], bool(row["is_active"]),
        )

    def update_password_hash(self, user_id: int, password_hash: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id)
            )

    # ── 暴力破解防护:失败计数 + 锁定窗口 ──────────────────────────
    def lockout_until(self, username: str) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT lockout_until FROM users WHERE username = ?", (username,)
            ).fetchone()
        return int(row["lockout_until"]) if row else 0

    def record_failure(self, username: str, max_failures: int, locked_until: int) -> None:
        """失败 +1;达阈值则写入锁定截止时间并清零计数,开始下一轮。"""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT failed_count FROM users WHERE username = ?", (username,)
            ).fetchone()
            if row is None:
                return
            count = int(row["failed_count"]) + 1
            if count >= max_failures:
                conn.execute(
                    "UPDATE users SET failed_count = 0, lockout_until = ? WHERE username = ?",
                    (locked_until, username),
                )
            else:
                conn.execute(
                    "UPDATE users SET failed_count = ? WHERE username = ?", (count, username)
                )

    def reset_failures(self, username: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE users SET failed_count = 0, lockout_until = 0 WHERE username = ?",
                (username,),
            )

    # ── 会话 ──────────────────────────────────────────────────────
    def create_session(
        self, token_hash: str, user_id: int, created_at: int, expires_at: int
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO sessions(token_hash, user_id, created_at, expires_at) "
                "VALUES(?,?,?,?)",
                (token_hash, user_id, created_at, expires_at),
            )

    def session_user(self, token_hash: str, now: int) -> User | None:
        """据令牌哈希取当事人;过期 / 失效 / 用户停用一律视为无效。"""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT u.id, u.username, u.display_name, u.password_hash, u.is_active, "
                "s.expires_at FROM sessions s JOIN users u ON u.id = s.user_id "
                "WHERE s.token_hash = ?",
                (token_hash,),
            ).fetchone()
        if row is None or int(row["expires_at"]) <= now or not bool(row["is_active"]):
            return None
        return User(
            row["id"], row["username"], row["display_name"],
            row["password_hash"], True,
        )

    def delete_session(self, token_hash: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))

    def purge_expired(self, now: int) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
