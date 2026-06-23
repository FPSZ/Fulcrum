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
from ..auth.permissions import PERMISSIONS
from .deps import AuthDeps
from .schemas import (
    ApproveRequest,
    DepartmentDTO,
    DepartmentWrite,
    PasswordReset,
    PermissionDTO,
    RoleDTO,
    RoleWrite,
    StatusUpdate,
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
    can_view = deps.require("users.view")
    can_manage_users = deps.require("users.manage")
    can_manage_dept = deps.require("dept.manage")
    can_manage_roles = deps.require("roles.manage")
    can_approve = deps.require("account.approve")

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
    async def create_role(body: RoleWrite, _: Principal = Depends(can_manage_roles)) -> RoleDTO:
        try:
            r = directory.create_role(body.name, body.description, body.permissions)
        except (NotFound, Conflict) as exc:
            _raise(exc)
        return _role_dto(r, 0)

    @app.patch("/admin/roles/{role_id}", response_model=RoleDTO)
    async def update_role(
        role_id: int, body: RoleWrite, _: Principal = Depends(can_manage_roles)
    ) -> RoleDTO:
        try:
            r = directory.update_role(
                role_id,
                name=body.name,
                description=body.description,
                permissions=body.permissions,
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
        _: Principal = Depends(can_view),
        department_id: int | None = Query(default=None),
        user_status: str | None = Query(default=None, alias="status"),
        role_id: int | None = Query(default=None),
        search: str | None = Query(default=None),
    ) -> list[UserDTO]:
        users = directory.list_users(
            department_id=department_id, status=user_status, role_id=role_id, search=search
        )
        return [_user_dto(u) for u in users]

    @app.get("/admin/users/stats", response_model=dict[str, int])
    async def user_stats(_: Principal = Depends(can_view)) -> dict[str, int]:
        return directory.status_counts()

    @app.post("/admin/users", response_model=TempPasswordResponse, status_code=201)
    async def create_user(
        body: UserCreate, _: Principal = Depends(can_manage_users)
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
            )
        except (NotFound, Conflict) as exc:
            _raise(exc)
        return TempPasswordResponse(user=_user_dto(user), temp_password=temp)

    @app.patch("/admin/users/{user_id}", response_model=UserDTO)
    async def update_user(
        user_id: int, body: UserUpdate, _: Principal = Depends(can_manage_users)
    ) -> UserDTO:
        fields = body.model_dump(exclude_unset=True)
        try:
            user = directory.update_user(user_id, fields=fields)
        except (NotFound, Conflict) as exc:
            _raise(exc)
        return _user_dto(user)

    @app.post("/admin/users/{user_id}/status", response_model=UserDTO)
    async def set_status(
        user_id: int, body: StatusUpdate, _: Principal = Depends(can_manage_users)
    ) -> UserDTO:
        try:
            user = directory.set_status(user_id, body.status)
        except (NotFound, Conflict) as exc:
            _raise(exc)
        return _user_dto(user)

    @app.post("/admin/users/{user_id}/reset-password", response_model=TempPasswordResponse)
    async def reset_password(
        user_id: int, body: PasswordReset, _: Principal = Depends(can_manage_users)
    ) -> TempPasswordResponse:
        try:
            temp = directory.reset_password(user_id, body.password)
        except (NotFound, Conflict) as exc:
            _raise(exc)
        target = directory.get_user(user_id)
        assert target is not None
        return TempPasswordResponse(user=_user_dto(target), temp_password=temp)

    @app.post("/admin/users/{user_id}/approve", response_model=UserDTO)
    async def approve(
        user_id: int, body: ApproveRequest, _: Principal = Depends(can_approve)
    ) -> UserDTO:
        try:
            user = directory.approve(user_id, body.role_id, body.department_id)
        except (NotFound, Conflict) as exc:
            _raise(exc)
        return _user_dto(user)

    @app.post("/admin/users/{user_id}/reject", status_code=204)
    async def reject(user_id: int, _: Principal = Depends(can_approve)) -> None:
        try:
            directory.reject(user_id)
        except (NotFound, Conflict) as exc:
            _raise(exc)
