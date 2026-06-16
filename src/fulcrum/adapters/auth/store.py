"""SQLite 用户/组织/角色/会话库 —— 鉴权与目录的持久化端口。

设计取舍:
- 每次操作开一条短连接(WAL 持久、开销极小);避免跨线程共享连接(FastAPI 同步路由跑线程池)。
- 会话存令牌的 SHA-256 而非令牌本身 —— 库被读走也拿不到可用令牌(单向)。
- 时间戳一律 UTC 纪元秒(整数),由上层注入,store 不自取时钟,便于测试与审计对齐。
- 失败计数/锁定窗口落库,暴力破解防护跨进程重启仍生效。
- 兼容升级:对已存在的 v1 users 表做列级迁移(ADD COLUMN),不丢历史数据。
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .models import (
    STATUS_ACTIVE,
    Department,
    Role,
    User,
)

# 区分"未提供该字段"与"显式置空(如把部门移到顶层 parent=None)"。
_UNSET: object = object()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS departments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL,
    parent_id  INTEGER REFERENCES departments(id) ON DELETE SET NULL,
    sort_order INTEGER NOT NULL DEFAULT 100,
    created_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS roles (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    key         TEXT    NOT NULL UNIQUE,
    name        TEXT    NOT NULL,
    description TEXT    NOT NULL DEFAULT '',
    is_system   INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id    INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission TEXT    NOT NULL,
    PRIMARY KEY (role_id, permission)
);
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    display_name  TEXT    NOT NULL,
    password_hash TEXT    NOT NULL,
    status        TEXT    NOT NULL DEFAULT 'active',
    employee_no   TEXT    NOT NULL DEFAULT '',
    email         TEXT    NOT NULL DEFAULT '',
    phone         TEXT    NOT NULL DEFAULT '',
    title         TEXT    NOT NULL DEFAULT '',
    department_id INTEGER REFERENCES departments(id) ON DELETE SET NULL,
    role_id       INTEGER REFERENCES roles(id) ON DELETE SET NULL,
    failed_count  INTEGER NOT NULL DEFAULT 0,
    lockout_until INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL DEFAULT 0,
    last_login_at INTEGER
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT    PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
"""

# v1 → 当前:旧 users 表可能缺这些列,逐列补齐。
_USER_MIGRATIONS = {
    "status": "TEXT NOT NULL DEFAULT 'active'",
    "employee_no": "TEXT NOT NULL DEFAULT ''",
    "email": "TEXT NOT NULL DEFAULT ''",
    "phone": "TEXT NOT NULL DEFAULT ''",
    "title": "TEXT NOT NULL DEFAULT ''",
    "department_id": "INTEGER",
    "role_id": "INTEGER",
    "last_login_at": "INTEGER",
}

_USER_COLS = (
    "id, username, display_name, password_hash, status, employee_no, email, phone, "
    "title, department_id, role_id, created_at, last_login_at"
)


def _to_user(row: sqlite3.Row) -> User:
    return User(
        id=row["id"],
        username=row["username"],
        display_name=row["display_name"],
        password_hash=row["password_hash"],
        status=row["status"],
        employee_no=row["employee_no"],
        email=row["email"],
        phone=row["phone"],
        title=row["title"],
        department_id=row["department_id"],
        role_id=row["role_id"],
        created_at=row["created_at"],
        last_login_at=row["last_login_at"],
    )


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
            cols = {r["name"] for r in conn.execute("PRAGMA table_info(users)")}
            for name, decl in _USER_MIGRATIONS.items():
                if name not in cols:
                    conn.execute(f"ALTER TABLE users ADD COLUMN {name} {decl}")
            # v1 旧行:有 is_active 但 status 仍是默认,据 is_active 归一到 status
            if "is_active" in cols and "status" not in cols:
                conn.execute(
                    "UPDATE users SET status = CASE WHEN is_active=0 THEN 'disabled' "
                    "ELSE 'active' END"
                )
            # 索引在补齐 department_id 列之后再建(兼容 v1 旧表)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_dept ON users(department_id)")

    # ── 部门 ──────────────────────────────────────────────────────
    def list_departments(self) -> list[Department]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, name, parent_id, sort_order FROM departments ORDER BY sort_order, id"
            ).fetchall()
        return [Department(r["id"], r["name"], r["parent_id"], r["sort_order"]) for r in rows]

    def create_department(
        self, name: str, parent_id: int | None, sort_order: int, now: int
    ) -> Department:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO departments(name, parent_id, sort_order, created_at) VALUES(?,?,?,?)",
                (name, parent_id, sort_order, now),
            )
            did = int(cur.lastrowid or 0)
        return Department(did, name, parent_id, sort_order)

    def update_department(
        self,
        dept_id: int,
        name: str | None = None,
        parent_id: int | None | object = _UNSET,
        sort_order: int | None = None,
    ) -> None:
        sets: list[str] = []
        args: list[object] = []
        if name is not None:
            sets.append("name = ?")
            args.append(name)
        if parent_id is not _UNSET:  # 仅在显式传入时改(含置空到顶层)
            sets.append("parent_id = ?")
            args.append(parent_id)
        if sort_order is not None:
            sets.append("sort_order = ?")
            args.append(sort_order)
        if not sets:
            return
        args.append(dept_id)
        with self._connect() as conn:
            conn.execute(f"UPDATE departments SET {', '.join(sets)} WHERE id = ?", args)

    def delete_department(self, dept_id: int) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM departments WHERE id = ?", (dept_id,))

    def department_has_children(self, dept_id: int) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM departments WHERE parent_id = ? LIMIT 1", (dept_id,)
            ).fetchone()
        return row is not None

    def department_member_count(self, dept_id: int) -> int:
        with self._connect() as conn:
            return int(
                conn.execute(
                    "SELECT COUNT(*) FROM users WHERE department_id = ?", (dept_id,)
                ).fetchone()[0]
            )

    # ── 角色 ──────────────────────────────────────────────────────
    def _role_perms(self, conn: sqlite3.Connection, role_id: int) -> frozenset[str]:
        rows = conn.execute(
            "SELECT permission FROM role_permissions WHERE role_id = ?", (role_id,)
        ).fetchall()
        return frozenset(r["permission"] for r in rows)

    def list_roles(self) -> list[Role]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, key, name, description, is_system FROM roles ORDER BY id"
            ).fetchall()
            return [
                Role(
                    r["id"],
                    r["key"],
                    r["name"],
                    r["description"],
                    bool(r["is_system"]),
                    self._role_perms(conn, r["id"]),
                )
                for r in rows
            ]

    def get_role(self, role_id: int) -> Role | None:
        with self._connect() as conn:
            r = conn.execute(
                "SELECT id, key, name, description, is_system FROM roles WHERE id = ?",
                (role_id,),
            ).fetchone()
            if r is None:
                return None
            return Role(
                r["id"],
                r["key"],
                r["name"],
                r["description"],
                bool(r["is_system"]),
                self._role_perms(conn, r["id"]),
            )

    def get_role_by_key(self, key: str) -> Role | None:
        with self._connect() as conn:
            r = conn.execute("SELECT id FROM roles WHERE key = ?", (key,)).fetchone()
        return self.get_role(r["id"]) if r else None

    def create_role(
        self,
        key: str,
        name: str,
        description: str,
        is_system: bool,
        permissions: list[str],
        now: int,
    ) -> Role:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO roles(key, name, description, is_system, created_at) "
                "VALUES(?,?,?,?,?)",
                (key, name, description, int(is_system), now),
            )
            rid = int(cur.lastrowid or 0)
            conn.executemany(
                "INSERT OR IGNORE INTO role_permissions(role_id, permission) VALUES(?,?)",
                [(rid, p) for p in permissions],
            )
        return Role(rid, key, name, description, is_system, frozenset(permissions))

    def update_role(
        self,
        role_id: int,
        name: str | None,
        description: str | None,
        permissions: list[str] | None,
    ) -> None:
        with self._connect() as conn:
            if name is not None:
                conn.execute("UPDATE roles SET name = ? WHERE id = ?", (name, role_id))
            if description is not None:
                conn.execute(
                    "UPDATE roles SET description = ? WHERE id = ?", (description, role_id)
                )
            if permissions is not None:
                conn.execute("DELETE FROM role_permissions WHERE role_id = ?", (role_id,))
                conn.executemany(
                    "INSERT OR IGNORE INTO role_permissions(role_id, permission) VALUES(?,?)",
                    [(role_id, p) for p in permissions],
                )

    def delete_role(self, role_id: int) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM roles WHERE id = ?", (role_id,))

    def role_member_count(self, role_id: int) -> int:
        with self._connect() as conn:
            return int(
                conn.execute("SELECT COUNT(*) FROM users WHERE role_id = ?", (role_id,)).fetchone()[
                    0
                ]
            )

    # ── 用户 ──────────────────────────────────────────────────────
    def count_users(self) -> int:
        with self._connect() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM users").fetchone()[0])

    def create_user(
        self,
        username: str,
        display_name: str,
        password_hash: str,
        status: str,
        now: int,
        *,
        employee_no: str = "",
        email: str = "",
        phone: str = "",
        title: str = "",
        department_id: int | None = None,
        role_id: int | None = None,
    ) -> User:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO users(username, display_name, password_hash, status, "
                "employee_no, email, phone, title, department_id, role_id, created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    username,
                    display_name,
                    password_hash,
                    status,
                    employee_no,
                    email,
                    phone,
                    title,
                    department_id,
                    role_id,
                    now,
                ),
            )
            uid = int(cur.lastrowid or 0)
        return User(
            id=uid,
            username=username,
            display_name=display_name,
            password_hash=password_hash,
            status=status,
            employee_no=employee_no,
            email=email,
            phone=phone,
            title=title,
            department_id=department_id,
            role_id=role_id,
            created_at=now,
            last_login_at=None,
        )

    def get_user(self, username: str) -> User | None:
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT {_USER_COLS} FROM users WHERE username = ?", (username,)
            ).fetchone()
        return _to_user(row) if row else None

    def get_user_by_id(self, user_id: int) -> User | None:
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT {_USER_COLS} FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        return _to_user(row) if row else None

    def list_users(
        self,
        *,
        department_ids: list[int] | None = None,
        status: str | None = None,
        role_id: int | None = None,
        search: str | None = None,
    ) -> list[User]:
        where, args = [], []
        if department_ids is not None:
            if not department_ids:
                return []
            where.append(f"department_id IN ({','.join('?' * len(department_ids))})")
            args.extend(department_ids)
        if status:
            where.append("status = ?")
            args.append(status)
        if role_id is not None:
            where.append("role_id = ?")
            args.append(role_id)
        if search:
            where.append("(username LIKE ? OR display_name LIKE ? OR employee_no LIKE ?)")
            like = f"%{search}%"
            args.extend([like, like, like])
        clause = f" WHERE {' AND '.join(where)}" if where else ""
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT {_USER_COLS} FROM users{clause} ORDER BY created_at DESC, id DESC",
                args,
            ).fetchall()
        return [_to_user(r) for r in rows]

    def count_by_status(self) -> dict[str, int]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT status, COUNT(*) AS n FROM users GROUP BY status"
            ).fetchall()
        return {r["status"]: int(r["n"]) for r in rows}

    def update_user_profile(self, user_id: int, fields: dict[str, object]) -> None:
        allowed = {
            "display_name",
            "employee_no",
            "email",
            "phone",
            "title",
            "department_id",
            "role_id",
            "status",
        }
        sets = [f"{k} = ?" for k in fields if k in allowed]
        args = [fields[k] for k in fields if k in allowed]
        if not sets:
            return
        args.append(user_id)
        with self._connect() as conn:
            conn.execute(f"UPDATE users SET {', '.join(sets)} WHERE id = ?", args)

    def update_password_hash(self, user_id: int, password_hash: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id)
            )

    def touch_last_login(self, user_id: int, now: int) -> None:
        with self._connect() as conn:
            conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now, user_id))

    # ── 暴力破解防护:失败计数 + 锁定窗口 ──────────────────────────
    def lockout_until(self, username: str) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT lockout_until FROM users WHERE username = ?", (username,)
            ).fetchone()
        return int(row["lockout_until"]) if row else 0

    def record_failure(self, username: str, max_failures: int, locked_until: int) -> None:
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
                "INSERT INTO sessions(token_hash, user_id, created_at, expires_at) VALUES(?,?,?,?)",
                (token_hash, user_id, created_at, expires_at),
            )

    def session_user(self, token_hash: str, now: int) -> User | None:
        """据令牌哈希取当事人;过期 / 非启用状态一律视为无效。"""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT u.id, u.username, u.display_name, u.password_hash, u.status, "
                "u.employee_no, u.email, u.phone, u.title, u.department_id, u.role_id, "
                "u.created_at, u.last_login_at, s.expires_at "
                "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?",
                (token_hash,),
            ).fetchone()
        if row is None or int(row["expires_at"]) <= now or row["status"] != STATUS_ACTIVE:
            return None
        return _to_user(row)

    def delete_session(self, token_hash: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))

    def delete_user_sessions(self, user_id: int) -> None:
        """停用/离职/改权限时,踢掉该用户所有在途会话。"""
        with self._connect() as conn:
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))

    def delete_user(self, user_id: int) -> None:
        """物理删除用户(仅用于驳回待审批申请:未激活、无历史)。"""
        with self._connect() as conn:
            conn.execute("DELETE FROM users WHERE id = ?", (user_id,))

    def purge_expired(self, now: int) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
