"""登录鉴权:口令哈希、会话签发/校验、锁定与抗枚举。"""

from __future__ import annotations

from pathlib import Path

import pytest

from fulcrum.adapters.auth import (
    AccountLocked,
    AuthService,
    InvalidCredentials,
    SQLiteAuthStore,
)
from fulcrum.adapters.auth.passwords import hash_password, verify_password


def test_password_hash_roundtrip() -> None:
    h = hash_password("S3cret-口令")
    assert h != "S3cret-口令"  # 不是明文
    assert verify_password(h, "S3cret-口令") is True
    assert verify_password(h, "wrong") is False


def test_two_hashes_differ_by_salt() -> None:
    assert hash_password("same") != hash_password("same")  # 盐随机 → 串不同


class _Clock:
    """可控时钟,驱动锁定窗口与会话过期的测试。"""

    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


def _service(tmp_path: Path, clock: _Clock, **kw: int) -> AuthService:
    store = SQLiteAuthStore(str(tmp_path / "auth.sqlite"))
    svc = AuthService(
        store,
        session_ttl_hours=kw.get("session_ttl_hours", 12),
        max_failures=kw.get("max_failures", 3),
        lockout_minutes=kw.get("lockout_minutes", 15),
        clock=clock,
    )
    svc.bootstrap_admin("admin", "correct horse")
    return svc


def test_bootstrap_only_once(tmp_path: Path) -> None:
    clock = _Clock()
    store = SQLiteAuthStore(str(tmp_path / "auth.sqlite"))
    svc = AuthService(store, session_ttl_hours=12, max_failures=3, lockout_minutes=15, clock=clock)
    assert svc.bootstrap_admin("admin", "pw") is not None  # 首次创建
    assert svc.bootstrap_admin("admin", "pw") is None  # 已有用户则跳过
    assert store.count_users() == 1


def test_generated_password_when_blank(tmp_path: Path) -> None:
    clock = _Clock()
    store = SQLiteAuthStore(str(tmp_path / "auth.sqlite"))
    svc = AuthService(store, session_ttl_hours=12, max_failures=3, lockout_minutes=15, clock=clock)
    pw = svc.bootstrap_admin("admin", "")  # 留空 → 随机生成
    assert pw and len(pw) >= 12
    assert svc.login("admin", pw)  # 生成的口令能登录


def test_login_success_then_authenticate(tmp_path: Path) -> None:
    clock = _Clock()
    svc = _service(tmp_path, clock)
    token = svc.login("admin", "correct horse")
    principal = svc.authenticate(token)
    assert principal is not None
    assert principal.username == "admin"


def test_wrong_password_rejected(tmp_path: Path) -> None:
    clock = _Clock()
    svc = _service(tmp_path, clock)
    with pytest.raises(InvalidCredentials):
        svc.login("admin", "nope")


def test_unknown_user_same_error(tmp_path: Path) -> None:
    clock = _Clock()
    svc = _service(tmp_path, clock)
    # 抗枚举:未知账号与错误口令报同一种错
    with pytest.raises(InvalidCredentials):
        svc.login("ghost", "whatever")


def test_lockout_after_max_failures(tmp_path: Path) -> None:
    clock = _Clock()
    svc = _service(tmp_path, clock, max_failures=3, lockout_minutes=15)
    for _ in range(3):
        with pytest.raises(InvalidCredentials):
            svc.login("admin", "bad")
    # 第 4 次即便口令正确也被锁定挡下
    with pytest.raises(AccountLocked):
        svc.login("admin", "correct horse")
    # 锁定窗口过后恢复
    clock.now += 15 * 60 + 1
    assert svc.login("admin", "correct horse")


def test_logout_revokes_session(tmp_path: Path) -> None:
    clock = _Clock()
    svc = _service(tmp_path, clock)
    token = svc.login("admin", "correct horse")
    assert svc.authenticate(token) is not None
    svc.logout(token)
    assert svc.authenticate(token) is None


def test_session_expires(tmp_path: Path) -> None:
    clock = _Clock()
    svc = _service(tmp_path, clock, session_ttl_hours=1)
    token = svc.login("admin", "correct horse")
    assert svc.authenticate(token) is not None
    clock.now += 3600 + 1  # 越过有效期
    assert svc.authenticate(token) is None


def test_authenticate_garbage_token(tmp_path: Path) -> None:
    clock = _Clock()
    svc = _service(tmp_path, clock)
    assert svc.authenticate(None) is None
    assert svc.authenticate("not-a-real-token") is None
