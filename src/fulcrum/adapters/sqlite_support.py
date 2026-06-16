"""SQLite 共享基建 —— 统一连接(WAL+外键)+ 基于 PRAGMA user_version 的迁移运行器。

**迁移约定(所有 SQLite 存储统一遵循,免得各库各自发明、积累迁移负债):**
- 每个库维护一串有序迁移 ``(Migration(1, fn), ...)``,version 从 1 连续递增。
- 启动时 ``run_migrations`` 读 ``PRAGMA user_version``,对高于当前的版本按序执行并抬升版本戳。
- 迁移**幂等、只进不退**;既有库(``user_version=0``)首启即被补迁到最新并打版本戳,不丢数据。
- 加 schema 变更 = **追加**更高 version 的迁移,**绝不改历史迁移**(否则破坏已迁移的生产库)。
- 连接走 ``connect()``:WAL + 外键 + Row 工厂 + 自动提交,每操作开短连接(开销极小)。

审计落库(P1)与任何新增 SQLite 存储都复用本模块,不重复发明迁移与连接。
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Migration:
    """一次 schema 迁移:version=目标版本号;apply=在连接上施加变更(必须幂等)。"""

    version: int
    apply: Callable[[sqlite3.Connection], None]


@contextmanager
def connect(path: str | Path) -> Iterator[sqlite3.Connection]:
    """标准 SQLite 短连接:WAL + 外键 + Row 工厂 + 自动提交(isolation_level=None)。"""
    conn = sqlite3.connect(str(path), isolation_level=None)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        yield conn
    finally:
        conn.close()


def run_migrations(conn: sqlite3.Connection, migrations: Sequence[Migration]) -> int:
    """按 PRAGMA user_version 施加尚未应用的迁移(version 升序),返回最终版本号。"""
    current = int(conn.execute("PRAGMA user_version").fetchone()[0])
    for migration in sorted(migrations, key=lambda m: m.version):
        if migration.version > current:
            migration.apply(conn)
            # PRAGMA 不支持参数绑定;version 是受控 int,f-string 安全。
            conn.execute(f"PRAGMA user_version = {int(migration.version)}")
            current = migration.version
    return current
