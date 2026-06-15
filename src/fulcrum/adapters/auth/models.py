"""鉴权域内只读数据结构(不含框架依赖)。"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class User:
    """用户主体。`password_hash` 仅在 store 内部流转,不出 API。"""

    id: int
    username: str
    display_name: str
    password_hash: str
    is_active: bool


@dataclass(frozen=True, slots=True)
class Principal:
    """通过会话校验后的当事人 —— 路由侧拿到的就是它,绝不暴露口令哈希。"""

    user_id: int
    username: str
    display_name: str
