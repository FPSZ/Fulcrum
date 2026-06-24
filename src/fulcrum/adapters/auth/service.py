"""AuthService —— 登录校验、会话签发/校验、账号申请、首启引导。

安全红线见 passwords/store;本层补充:
- 登录先校验口令、再看状态:错口令不泄露"账号是否存在/是否待审批"。
- 申请账号(register)落为 pending,需管理员审批才能登录。
- 会话校验时按角色加载**生效权限点**,组装进 Principal(供 require_permission / 前端按权过滤)。
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import time
from collections.abc import Callable

from .models import (
    STATUS_ACTIVE,
    STATUS_PENDING,
    Principal,
)
from .passwords import hash_password, needs_rehash, verify_password
from .permissions import (
    BUILTIN_DEPARTMENTS,
    BUILTIN_ROLES,
    DEFAULT_BOOTSTRAP_ROLE,
)
from .store import SQLiteAuthStore

logger = logging.getLogger("fulcrum.auth")

_DUMMY_PLAIN = "fulcrum-timing-equalizer"
_MIN_PASSWORD_LEN = 8


class AuthError(Exception):
    """鉴权失败基类。"""


class InvalidCredentials(AuthError):
    """账号或口令错误(对外信息统一,不区分哪项错)。"""


class AccountLocked(AuthError):
    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__("账号已被临时锁定,请稍后再试")
        self.retry_after_seconds = retry_after_seconds


class PendingApproval(AuthError):
    """账号已提交申请,待管理员审批。"""

    def __init__(self) -> None:
        super().__init__("账号正在等待管理员审批")


class AccountDisabled(AuthError):
    """账号被停用或已离职。"""

    def __init__(self) -> None:
        super().__init__("账号已被停用,请联系管理员")


class UsernameTaken(AuthError):
    def __init__(self) -> None:
        super().__init__("该账号已存在")


class WeakPassword(AuthError):
    def __init__(self) -> None:
        super().__init__(f"口令至少需要 {_MIN_PASSWORD_LEN} 位")


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

    # ── 种子:角色目录 + 组织架构 + 首启管理员 ────────────────────
    def seed(self, admin_username: str, admin_password: str) -> str | None:
        """幂等装配:补齐内置角色与部门,库内无用户时引导管理员。"""
        self._seed_roles()
        self._seed_departments()
        return self._bootstrap_admin(admin_username, admin_password)

    def _seed_roles(self) -> None:
        if self._store.list_roles() or self._store.count_users() > 0:
            return
        now = self._now()
        for seed in BUILTIN_ROLES:
            self._store.create_role(
                seed.key,
                seed.name,
                seed.description,
                True,
                list(seed.permissions),
                now,
                scope=seed.scope,
            )

    def _seed_departments(self) -> None:
        if self._store.list_departments():
            return
        now = self._now()
        key_to_id: dict[str, int] = {}
        for order, seed in enumerate(BUILTIN_DEPARTMENTS):
            parent_id = key_to_id.get(seed.parent_key) if seed.parent_key else None
            dept = self._store.create_department(seed.name, parent_id, (order + 1) * 10, now)
            key_to_id[seed.key] = dept.id

    def _bootstrap_admin(self, username: str, password: str) -> str | None:
        if self._store.count_users() > 0:
            return None
        generated = not password
        pwd = password or secrets.token_urlsafe(15)
        role = self._store.get_role_by_key(DEFAULT_BOOTSTRAP_ROLE)
        root = next(iter(self._store.list_departments()), None)
        self._store.create_user(
            username,
            "系统管理员",
            hash_password(pwd),
            STATUS_ACTIVE,
            self._now(),
            title="平台管理员",
            role_id=role.id if role else None,
            department_id=root.id if root else None,
        )
        logger.warning("已创建初始管理员账号:%s", username)
        if generated:
            logger.warning(
                "未配置 FULCRUM_BOOTSTRAP_ADMIN_PASSWORD,已随机生成初始口令(仅打印这一次):%s",
                pwd,
            )
        return pwd

    # ── 申请账号(公开):落为 pending,待审批 ─────────────────────
    def register(self, username: str, password: str, display_name: str) -> None:
        username = username.strip()
        if not username or not display_name.strip():
            raise InvalidCredentials("请填写账号与姓名")
        if len(password) < _MIN_PASSWORD_LEN:
            raise WeakPassword()
        if self._store.get_user(username) is not None:
            raise UsernameTaken()
        self._store.create_user(
            username,
            display_name.strip(),
            hash_password(password),
            STATUS_PENDING,
            self._now(),
        )
        logger.info("收到账号申请:%s", username)

    # ── 登录 ──────────────────────────────────────────────────────
    def login(self, username: str, password: str) -> str:
        username = username.strip()
        now = self._now()

        locked_until = self._store.lockout_until(username)
        if locked_until > now:
            raise AccountLocked(locked_until - now)

        user = self._store.get_user(username)
        if user is None:
            verify_password(self._dummy_hash, password)  # 抗枚举:等价耗时
            self._fail(username, now)
            raise InvalidCredentials("账号或口令错误")

        if not verify_password(user.password_hash, password):
            self._fail(username, now)
            logger.warning("登录失败:账号=%s", username)
            raise InvalidCredentials("账号或口令错误")

        # 口令正确后才暴露账号状态,避免据此探测账号。
        if user.status == STATUS_PENDING:
            self._store.reset_failures(username)
            raise PendingApproval()
        if user.status != STATUS_ACTIVE:
            self._store.reset_failures(username)
            raise AccountDisabled()

        if needs_rehash(user.password_hash):
            self._store.update_password_hash(user.id, hash_password(password))
        self._store.reset_failures(username)

        token = secrets.token_urlsafe(32)
        self._store.create_session(self._hash_token(token), user.id, now, now + self._ttl)
        self._store.touch_last_login(user.id, now)
        self._store.purge_expired(now)
        logger.info("登录成功:账号=%s", username)
        return token

    def _fail(self, username: str, now: int) -> None:
        self._store.record_failure(username, self._max_failures, now + self._lockout)

    # ── 会话令牌 → 当事人(含生效权限点)──────────────────────────
    def authenticate(self, token: str | None) -> Principal | None:
        if not token:
            return None
        user = self._store.session_user(self._hash_token(token), self._now())
        if user is None:
            return None
        role = self._store.get_role(user.role_id) if user.role_id is not None else None
        memberships = self._store.list_user_memberships(user.id)
        team_ids = frozenset(m.team_id for m in memberships)
        lead_roots = {m.team_id for m in memberships if m.is_lead}
        managed_teams = self._expand_subtrees(lead_roots) if lead_roots else frozenset()
        return Principal(
            user_id=user.id,
            username=user.username,
            display_name=user.display_name,
            role_key=role.key if role else None,
            role_name=role.name if role else None,
            permissions=role.permissions if role else frozenset(),
            team_ids=team_ids,
            managed_teams=managed_teams,
        )

    def _expand_subtrees(self, roots: set[int]) -> frozenset[int]:
        """把一组团队 id 展开成"含自身的整棵子树"并集(团队负责人覆盖其下全部子团队)。"""
        children: dict[int, list[int]] = {}
        for d in self._store.list_departments():
            if d.parent_id is not None:
                children.setdefault(d.parent_id, []).append(d.id)
        out: set[int] = set()
        stack = list(roots)
        while stack:
            cur = stack.pop()
            if cur in out:
                continue
            out.add(cur)
            stack.extend(children.get(cur, []))
        return frozenset(out)

    def logout(self, token: str | None) -> None:
        if token:
            self._store.delete_session(self._hash_token(token))

    @property
    def session_ttl_seconds(self) -> int:
        return self._ttl
