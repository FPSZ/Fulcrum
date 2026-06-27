"""管理后台路由 —— 组织/角色/成员/权限(全部经 require_permission 强制鉴权)。

REST 映射 DirectoryService;一致性/护栏违例 → 409,找不到 → 404。
"""

from __future__ import annotations

from typing import NoReturn

from fastapi import Depends, FastAPI, HTTPException, Query, status

from ..auth import (
    Conflict,
    Department,
    DirectoryService,
    NotFound,
    Principal,
    Role,
    User,
)
from ..auth.models import ROLE_SCOPE_TEAM
from ..auth.permissions import PERMISSIONS
from .deps import AuthDeps
from .schemas import (
    ApproveRequest,
    DepartmentDTO,
    DepartmentWrite,
    MembershipDTO,
    PasswordReset,
    PermissionDTO,
    RoleDTO,
    RoleUpdate,
    RoleWrite,
    StatusUpdate,
    TeamMemberWrite,
    TempPasswordResponse,
    UserCreate,
    UserDTO,
    UserUpdate,
)


def _dept_dto(d: Department, member_count: int) -> DepartmentDTO:
    return DepartmentDTO(
        id=d.id,
        name=d.name,
        parent_id=d.parent_id,
        sort_order=d.sort_order,
        member_count=member_count,
    )


def _role_dto(r: Role, member_count: int) -> RoleDTO:
    return RoleDTO(
        id=r.id,
        key=r.key,
        name=r.name,
        description=r.description,
        is_system=r.is_system,
        permissions=sorted(r.permissions),
        member_count=member_count,
        scope=r.scope,
    )


def _user_dto(u: User) -> UserDTO:
    return UserDTO(
        id=u.id,
        username=u.username,
        display_name=u.display_name,
        status=u.status,
        employee_no=u.employee_no,
        email=u.email,
        phone=u.phone,
        title=u.title,
        department_id=u.department_id,
        role_id=u.role_id,
        created_at=u.created_at,
        last_login_at=u.last_login_at,
    )


def _raise(exc: NotFound | Conflict) -> NoReturn:
    code = status.HTTP_404_NOT_FOUND if isinstance(exc, NotFound) else status.HTTP_409_CONFLICT
    raise HTTPException(status_code=code, detail=str(exc)) from exc


def register_admin_routes(app: FastAPI, directory: DirectoryService, deps: AuthDeps) -> None:
    can_view = deps.require_member_reader()  # users.view 或团队负责人(成员列表行级过滤)
    can_view_stats = deps.require("users.view")  # 全局统计仍限组织级读权
    can_manage_users = deps.require("users.manage")
    can_admin_members = deps.require_member_admin()  # 组织管理员 或 团队负责人
    can_manage_dept = deps.require("dept.manage")
    can_manage_roles = deps.require("roles.manage")
    can_approve = deps.require_approver()  # 组织级审批人 或 团队负责人(范围由处理器复校)

    def _target_team_ids(user: User) -> set[int]:
        """目标成员归属的团队集合(成员关系 + 兼容旧 department_id)。"""
        teams = {m.team_id for m in directory.list_user_teams(user.id)}
        if user.department_id is not None:
            teams.add(user.department_id)
        return teams

    def _ensure_can_manage(principal: Principal, target: User) -> None:
        """复校:组织级 users.manage 放行;否则目标必须落在本人可管的团队子树内。"""
        if principal.has("users.manage"):
            return
        teams = _target_team_ids(target)
        if not teams or not (teams & principal.managed_teams):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="只能管理你所负责团队内的成员"
            )

    def _guard_lead_mutation(principal: Principal, fields: dict) -> None:
        """团队负责人的边界(非组织管理员时):不得改派角色、不得把成员移出自己管的团队。

        防越权升级——团队负责人不能给人安插组织级角色,也不能把人挪到管不到的团队。
        角色改派 / 跨团队调动仍归组织管理员(users.manage)。
        """
        if principal.has("users.manage"):
            return
        if "role_id" in fields:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="团队负责人不能改派成员角色"
            )
        new_dept = fields.get("department_id")
        if new_dept is not None and new_dept not in principal.managed_teams:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="不能把成员移出你负责的团队"
            )

    def _guard_approve(
        principal: Principal, target: User, role_id: int | None, department_id: int | None
    ) -> None:
        """审批下放范围闸(plan/13 §6):组织级 account.approve 不限;团队负责人只能把账号审进
        自己负责的团队、且只能赋团队级角色——防借审批跨团队安插或提权为组织级角色。"""
        if principal.has("account.approve"):
            return
        managed = principal.managed_teams
        if not managed:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="你没有账号审批权")
        if target.department_id is not None and target.department_id not in managed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="该申请属于其他团队,你无权审批"
            )
        if department_id is None or department_id not in managed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="团队负责人只能把账号审批进你负责的团队",
            )
        if role_id is not None:
            role = next((r for r in directory.list_roles() if r.id == role_id), None)
            if role is None or role.scope != ROLE_SCOPE_TEAM:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="团队负责人只能赋予团队级角色"
                )

    def _guard_reject(principal: Principal, target: User) -> None:
        """驳回下放范围闸:团队负责人只能驳回"申请加入本团队"的待审账号。"""
        if principal.has("account.approve"):
            return
        managed = principal.managed_teams
        if not managed or target.department_id is None or target.department_id not in managed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="团队负责人只能驳回本团队的待审批申请"
            )

    # ── 权限目录 ──────────────────────────────────────────────────
    @app.get("/admin/permissions", response_model=list[PermissionDTO])
    async def permissions(_: Principal = Depends(can_view)) -> list[PermissionDTO]:
        return [
            PermissionDTO(
                key=p.key,
                label=p.label,
                group=p.group,
                capability=p.capability,
                cap_label=p.cap_label,
                access=p.access,
            )
            for p in PERMISSIONS
        ]

    # ── 组织架构 ──────────────────────────────────────────────────
    @app.get("/admin/departments", response_model=list[DepartmentDTO])
    async def list_departments(_: Principal = Depends(can_view)) -> list[DepartmentDTO]:
        return [
            _dept_dto(d, directory.department_member_count(d.id))
            for d in directory.list_departments()
        ]

    @app.post("/admin/departments", response_model=DepartmentDTO, status_code=201)
    async def create_department(
        body: DepartmentWrite, _: Principal = Depends(can_manage_dept)
    ) -> DepartmentDTO:
        try:
            d = directory.create_department(body.name, body.parent_id, body.sort_order or 100)
        except (NotFound, Conflict) as exc:
            _raise(exc)
        return _dept_dto(d, 0)

    @app.patch("/admin/departments/{dept_id}", response_model=DepartmentDTO)
    async def update_department(
        dept_id: int, body: DepartmentWrite, _: Principal = Depends(can_manage_dept)
    ) -> DepartmentDTO:
        try:
            d = directory.update_department(
                dept_id,
                name=body.name,
                parent_id=body.parent_id,
                sort_order=body.sort_order,
                change_parent=True,
            )
        except (NotFound, Conflict) as exc:
            _raise(exc)
        return _dept_dto(d, directory.department_member_count(d.id))

    @app.delete("/admin/departments/{dept_id}", status_code=204)
    async def delete_department(dept_id: int, _: Principal = Depends(can_manage_dept)) -> None:
        try:
            directory.delete_department(dept_id)
        except (NotFound, Conflict) as exc:
            _raise(exc)

    # ── 角色与权限 ────────────────────────────────────────────────
    @app.get("/admin/roles", response_model=list[RoleDTO])
    async def list_roles(_: Principal = Depends(can_view)) -> list[RoleDTO]:
        return [_role_dto(r, directory.role_member_count(r.id)) for r in directory.list_roles()]

    @app.post("/admin/roles", response_model=RoleDTO, status_code=201)
    async def create_role(
        body: RoleWrite, principal: Principal = Depends(can_manage_roles)
    ) -> RoleDTO:
        try:
            r = directory.create_role(
                body.name,
                body.description,
                body.permissions,
                body.scope,
                actor_permissions=principal.permissions,
            )
        except (NotFound, Conflict) as exc:
            _raise(exc)
        return _role_dto(r, 0)

    @app.patch("/admin/roles/{role_id}", response_model=RoleDTO)
    async def update_role(
        role_id: int, body: RoleUpdate, principal: Principal = Depends(can_manage_roles)
    ) -> RoleDTO:
        fields = body.model_dump(exclude_unset=True)
        try:
            r = directory.update_role(
                role_id,
                name=fields.get("name"),
                description=fields.get("description"),
                permissions=fields.get("permissions"),
                actor_permissions=principal.permissions,
            )
        except (NotFound, Conflict) as exc:
            _raise(exc)
        return _role_dto(r, directory.role_member_count(r.id))

    @app.delete("/admin/roles/{role_id}", status_code=204)
    async def delete_role(role_id: int, _: Principal = Depends(can_manage_roles)) -> None:
        try:
            directory.delete_role(role_id)
        except (NotFound, Conflict) as exc:
            _raise(exc)

    # ── 成员 ──────────────────────────────────────────────────────
    @app.get("/admin/users", response_model=list[UserDTO])
    async def list_users(
        principal: Principal = Depends(can_view),
        department_id: int | None = Query(default=None),
        user_status: str | None = Query(default=None, alias="status"),
        role_id: int | None = Query(default=None),
        search: str | None = Query(default=None),
    ) -> list[UserDTO]:
        users = directory.list_users(
            department_id=department_id, status=user_status, role_id=role_id, search=search
        )
        # 纯团队负责人(无组织级 users.view)只见本人可管团队子树内的成员(plan/13 §6 行级过滤)。
        if not principal.has("users.view"):
            users = [u for u in users if _target_team_ids(u) & principal.managed_teams]
        return [_user_dto(u) for u in users]

    @app.get("/admin/users/stats", response_model=dict[str, int])
    async def user_stats(_: Principal = Depends(can_view_stats)) -> dict[str, int]:
        return directory.status_counts()

    @app.post("/admin/users", response_model=TempPasswordResponse, status_code=201)
    async def create_user(
        body: UserCreate, principal: Principal = Depends(can_manage_users)
    ) -> TempPasswordResponse:
        try:
            user, temp = directory.create_user(
                username=body.username,
                display_name=body.display_name,
                role_id=body.role_id,
                department_id=body.department_id,
                password=body.password,
                employee_no=body.employee_no,
                email=body.email,
                phone=body.phone,
                title=body.title,
                actor_permissions=principal.permissions,
            )
        except (NotFound, Conflict) as exc:
            _raise(exc)
        return TempPasswordResponse(user=_user_dto(user), temp_password=temp)

    @app.patch("/admin/users/{user_id}", response_model=UserDTO)
    async def update_user(
        user_id: int, body: UserUpdate, principal: Principal = Depends(can_admin_members)
    ) -> UserDTO:
        target = directory.get_user(user_id)
        if target is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="成员不存在")
        _ensure_can_manage(principal, target)
        fields = body.model_dump(exclude_unset=True)
        _guard_lead_mutation(principal, fields)
        try:
            user = directory.update_user(
                user_id, fields=fields, actor_permissions=principal.permissions
            )
        except (NotFound, Conflict) as exc:
            _raise(exc)
        return _user_dto(user)

    @app.post("/admin/users/{user_id}/status", response_model=UserDTO)
    async def set_status(
        user_id: int, body: StatusUpdate, principal: Principal = Depends(can_admin_members)
    ) -> UserDTO:
        target = directory.get_user(user_id)
        if target is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="成员不存在")
        _ensure_can_manage(principal, target)
        try:
            user = directory.set_status(user_id, body.status)
        except (NotFound, Conflict) as exc:
            _raise(exc)
        return _user_dto(user)

    @app.post("/admin/users/{user_id}/reset-password", response_model=TempPasswordResponse)
    async def reset_password(
        user_id: int, body: PasswordReset, principal: Principal = Depends(can_admin_members)
    ) -> TempPasswordResponse:
        target = directory.get_user(user_id)
        if target is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="成员不存在")
        _ensure_can_manage(principal, target)
        try:
            temp = directory.reset_password(user_id, body.password)
        except (NotFound, Conflict) as exc:
            _raise(exc)
        target = directory.get_user(user_id)
        assert target is not None
        return TempPasswordResponse(user=_user_dto(target), temp_password=temp)

    @app.post("/admin/users/{user_id}/approve", response_model=UserDTO)
    async def approve(
        user_id: int, body: ApproveRequest, principal: Principal = Depends(can_approve)
    ) -> UserDTO:
        target = directory.get_user(user_id)
        if target is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="账号不存在")
        _guard_approve(principal, target, body.role_id, body.department_id)
        try:
            user = directory.approve(
                user_id,
                body.role_id,
                body.department_id,
                actor_permissions=principal.permissions,
            )
        except (NotFound, Conflict) as exc:
            _raise(exc)
        return _user_dto(user)

    @app.post("/admin/users/{user_id}/reject", status_code=204)
    async def reject(user_id: int, principal: Principal = Depends(can_approve)) -> None:
        target = directory.get_user(user_id)
        if target is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="账号不存在")
        _guard_reject(principal, target)
        try:
            directory.reject(user_id)
        except (NotFound, Conflict) as exc:
            _raise(exc)

    # ── 团队成员关系(负责人管本团队;plan/13 P1b.3)──────────────────
    @app.get("/admin/teams/{team_id}/members", response_model=list[MembershipDTO])
    async def team_members(team_id: int, _: Principal = Depends(can_view)) -> list[MembershipDTO]:
        return [
            MembershipDTO(
                user_id=m.user_id, team_id=m.team_id, team_role=m.team_role, is_lead=m.is_lead
            )
            for m in directory.list_team_members(team_id)
        ]

    @app.post("/admin/teams/{team_id}/members", response_model=MembershipDTO)
    async def add_team_member(
        team_id: int, body: TeamMemberWrite, principal: Principal = Depends(can_admin_members)
    ) -> MembershipDTO:
        if not principal.can_manage_team(team_id):  # 只能往自己负责的团队加人
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="只能管理你负责的团队成员"
            )
        try:
            m = directory.add_team_member(team_id, body.user_id, body.team_role, body.is_lead)
        except (NotFound, Conflict) as exc:
            _raise(exc)
        return MembershipDTO(
            user_id=m.user_id, team_id=m.team_id, team_role=m.team_role, is_lead=m.is_lead
        )

    @app.delete("/admin/teams/{team_id}/members/{user_id}", status_code=204)
    async def remove_team_member(
        team_id: int, user_id: int, principal: Principal = Depends(can_admin_members)
    ) -> None:
        if not principal.can_manage_team(team_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="只能管理你负责的团队成员"
            )
        try:
            directory.remove_team_member(team_id, user_id)
        except (NotFound, Conflict) as exc:
            _raise(exc)
