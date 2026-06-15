"""AuthService —— 账号口令校验 + 服务端会话签发/校验的应用编排。

安全红线(逐条对应实现):
- 口令只存 Argon2id 哈希,明文不落库、不入日志。            → passwords + store
- 会话用 256bit 随机不透明令牌;库内只存其 SHA-256。         → login / store
- 失败有锁定窗口,挡暴力破解。                              → login + store
- 抗用户枚举:账号不存在时也跑一次等价哈希校验,登录失败信息统一。 → login(_dummy)
- 令牌过期 / 用户停用 → 会话立即失效。                       → store.session_user
- 退出即撤销服务端会话(不是只删 Cookie)。                  → logout
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import time
from collections.abc import Callable

from .models import Principal
from .passwords import hash_password, needs_rehash, verify_password
from .store import SQLiteAuthStore

logger = logging.getLogger("fulcrum.auth")

# 抗用户枚举:对一段固定明文预算一个哈希,账号不存在时拿它走一遍校验,
# 让"用户存在/不存在"两条路径耗时接近,避免据响应时间探测账号。
_DUMMY_PLAIN = "fulcrum-timing-equalizer"


class AuthError(Exception):
    """鉴权失败基类。"""


class InvalidCredentials(AuthError):
    """账号或口令错误(信息对外统一,不区分是哪一项错)。"""


class AccountLocked(AuthError):
    """连续失败过多,账号临时锁定。"""

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__("账号已被临时锁定,请稍后再试")
        self.retry_after_seconds = retry_after_seconds


class AuthService:
    def __init__(
        self,
        store: SQLiteAuthStore,
        *,
        session_ttl_hours: int,
        max_failures: int,
        lockout_minutes: int,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._store = store
        self._ttl = session_ttl_hours * 3600
        self._max_failures = max_failures
        self._lockout = lockout_minutes * 60
        self._clock = clock
        self._dummy_hash = hash_password(_DUMMY_PLAIN)

    def _now(self) -> int:
        return int(self._clock())

    @staticmethod
    def _hash_token(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    # ── 引导:首次启动且库内无用户时创建管理员 ────────────────────
    def bootstrap_admin(self, username: str, password: str) -> str | None:
        """库内已有用户则跳过;否则创建管理员。

        返回值:None=已存在用户(未创建);否则返回所用口令明文(供"随机生成"时打印一次)。
        """
        if self._store.count_users() > 0:
            return None
        generated = not password
        pwd = password or secrets.token_urlsafe(15)
        self._store.create_user(username, "系统管理员", hash_password(pwd), self._now())
        logger.warning("已创建初始管理员账号:%s", username)
        if generated:
            logger.warning(
                "未配置 FULCRUM_BOOTSTRAP_ADMIN_PASSWORD,已随机生成初始口令(仅打印这一次):%s",
                pwd,
            )
        return pwd

    # ── 登录:校验通过则签发会话,返回原始令牌(仅此一次可见)─────
    def login(self, username: str, password: str) -> str:
        username = username.strip()
        now = self._now()

        locked_until = self._store.lockout_until(username)
        if locked_until > now:
            raise AccountLocked(locked_until - now)

        user = self._store.get_user(username)
        # 抗枚举:无此用户也走一遍等价校验,再统一报错。
        if user is None or not user.is_active:
            verify_password(self._dummy_hash, password)
            self._fail(username, now)
            raise InvalidCredentials("账号或口令错误")

        if not verify_password(user.password_hash, password):
            self._fail(username, now)
            logger.warning("登录失败:账号=%s", username)
            raise InvalidCredentials("账号或口令错误")

        # 校验通过:参数过时则顺手用更强参数重存哈希(透明升级)。
        if needs_rehash(user.password_hash):
            self._store.update_password_hash(user.id, hash_password(password))
        self._store.reset_failures(username)

        token = secrets.token_urlsafe(32)
        self._store.create_session(self._hash_token(token), user.id, now, now + self._ttl)
        self._store.purge_expired(now)
        logger.info("登录成功:账号=%s", username)
        return token

    def _fail(self, username: str, now: int) -> None:
        self._store.record_failure(username, self._max_failures, now + self._lockout)

    # ── 校验会话令牌 → 当事人 ─────────────────────────────────────
    def authenticate(self, token: str | None) -> Principal | None:
        if not token:
            return None
        user = self._store.session_user(self._hash_token(token), self._now())
        if user is None:
            return None
        return Principal(user.id, user.username, user.display_name)

    # ── 退出:撤销服务端会话 ──────────────────────────────────────
    def logout(self, token: str | None) -> None:
        if token:
            self._store.delete_session(self._hash_token(token))

    @property
    def session_ttl_seconds(self) -> int:
        return self._ttl
