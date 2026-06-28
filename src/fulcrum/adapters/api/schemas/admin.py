"""管理后台 DTO —— 登录/账号、控制台设置、权限/角色/组织/成员。"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "BackendModelInfo",
    "ConsoleSettingsWrite",
    "ConsoleSettingsPublic",
    "LoginRequest",
    "RegisterRequest",
    "PrincipalResponse",
    "PermissionDTO",
    "DepartmentDTO",
    "DepartmentWrite",
    "MembershipDTO",
    "TeamMemberWrite",
    "RoleDTO",
    "RoleWrite",
    "RoleUpdate",
    "UserDTO",
    "UserCreate",
    "UserUpdate",
    "StatusUpdate",
    "PasswordReset",
    "ApproveRequest",
    "TempPasswordResponse",
]


# ---- /admin/settings(控制台实例设置:真实可写项 + 运行态只读信息)----
class BackendModelInfo(BaseModel):
    """只读:后端模型出站配置(经 .env 注入,不在控制台改;此处仅如实回显)。"""

    endpoint: str
    model_name: str
    key_set: bool


class ConsoleSettingsWrite(BaseModel):
    """更新控制台实例元信息(真实落盘字段)。"""

    model_config = ConfigDict(extra="forbid")

    instance_name: str = Field(default="枢衡安全控制台", max_length=64)
    environment: str = Field(default="demo", pattern="^(prod|staging|demo)$")


class ConsoleSettingsPublic(ConsoleSettingsWrite):
    """回前端:真实可写项 + 只读后端模型信息。"""

    backend_model: BackendModelInfo


# ---- /auth ----
class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class RegisterRequest(BaseModel):
    """申请账号:申请人自填账号口令与姓名,落为待审批。"""

    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=8, max_length=256)
    display_name: str = Field(min_length=1, max_length=128)


class PrincipalResponse(BaseModel):
    """当前登录主体(绝不含口令哈希或会话令牌)。"""

    username: str
    display_name: str
    role_key: str | None = None
    role_name: str | None = None
    permissions: list[str] = Field(default_factory=list)
    # 团队范围(plan/13):所属团队 + 作为负责人可管的团队(已展开子树)。
    # 前端据 managed_teams 是否非空判「我是不是团队负责人」,据此放出成员/团队/审批等管理界面。
    team_ids: list[int] = Field(default_factory=list)
    managed_teams: list[int] = Field(default_factory=list)


# ---- 权限 / 角色 / 组织 / 成员(管理后台)----
class PermissionDTO(BaseModel):
    key: str
    label: str
    group: str
    capability: str  # 能力域 id(成对看/改共享,前端合成只读/读写三态)
    cap_label: str  # 能力域中文名(展示一行)
    access: str  # read | write | action


class DepartmentDTO(BaseModel):
    id: int
    name: str
    parent_id: int | None = None
    sort_order: int = 100
    member_count: int = 0


class DepartmentWrite(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    parent_id: int | None = None
    sort_order: int | None = None


class MembershipDTO(BaseModel):
    """成员在某团队的归属(plan/13 P1b):团队内角色 + 是否负责人。"""

    user_id: int
    team_id: int
    team_role: str = "member"
    is_lead: bool = False


class TeamMemberWrite(BaseModel):
    """把某成员加入/更新到某团队(团队负责人或组织管理员可调)。"""

    user_id: int
    team_role: str = Field(default="member", max_length=64)
    is_lead: bool = False


class RoleDTO(BaseModel):
    id: int
    key: str
    name: str
    description: str = ""
    is_system: bool = False
    permissions: list[str] = Field(default_factory=list)
    member_count: int = 0
    scope: str = "org"  # org=组织级(全局) | team=团队级(团队内模板)


class RoleWrite(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    description: str = ""
    permissions: list[str] = Field(default_factory=list)
    scope: str = Field(default="team", pattern="^(org|team)$")  # 自定义角色默认团队级


class RoleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=64)
    description: str | None = None
    permissions: list[str] | None = None


class UserDTO(BaseModel):
    """成员详情(管理后台用)。绝不含口令哈希。"""

    id: int
    username: str
    display_name: str
    status: str
    employee_no: str = ""
    email: str = ""
    phone: str = ""
    title: str = ""
    department_id: int | None = None
    role_id: int | None = None
    created_at: int = 0
    last_login_at: int | None = None


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    display_name: str = Field(min_length=1, max_length=128)
    password: str | None = Field(default=None, max_length=256)
    role_id: int | None = None
    department_id: int | None = None
    employee_no: str = ""
    email: str = ""
    phone: str = ""
    title: str = ""


class UserUpdate(BaseModel):
    display_name: str | None = Field(default=None, max_length=128)
    role_id: int | None = None
    department_id: int | None = None
    employee_no: str | None = None
    email: str | None = None
    phone: str | None = None
    title: str | None = None


class StatusUpdate(BaseModel):
    status: str = Field(pattern="^(active|disabled|left)$")


class PasswordReset(BaseModel):
    password: str | None = Field(default=None, max_length=256)


class ApproveRequest(BaseModel):
    role_id: int | None = None
    department_id: int | None = None


class TempPasswordResponse(BaseModel):
    """新建成员 / 重置口令:仅这一次返回临时口令(若由系统生成)。"""

    user: UserDTO
    temp_password: str | None = None
