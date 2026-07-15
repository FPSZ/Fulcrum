"""写操作的提案-确认-撤销执行器(plan/11 §6)—— 人闸在中间,写执行不在 chat 循环里发生。

三件套:
- `ActionTokenSigner`:对工具、主体、服务端会话和过期时间签发**防篡改令牌**(HMAC)。
  提案随 chat 产出 token;确认会校验过期、工具、主体和会话。
  编辑参数在确认时经 schema 校验和 RBAC 复校。
- `UndoStore`:记每个已执行写操作的**前态快照**(一次性句柄),供一键撤销回滚。
- `AssistantActuator.confirm/undo`:纵深 RBAC + 执行 write handler / undo_handler + 写审计
  (ASSISTANT_ACTED / ASSISTANT_UNDONE)。底层调的就是各服务方法,与 REST 写端点同一套校验。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from ...core.domain import AuditEvent, AuditEventType
from ...core.operations import AssistantTool, OperationRegistry
from ...core.redaction import redact
from .services import AssistantServices

_TOKEN_TTL = 600.0  # 提案令牌有效期(秒);过期需重新发起提案。


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


class ActionTokenSigner:
    """HMAC 签发/校验提案令牌。密钥进程内随机(不落盘、不入前端)。"""

    def __init__(self, *, key: bytes | None = None, ttl: float = _TOKEN_TTL) -> None:
        self._key = key or secrets.token_bytes(32)
        self._ttl = ttl

    def issue(self, *, tool: str, actor: str, session_id: str, now: float | None = None) -> str:
        exp = (now if now is not None else time.time()) + self._ttl
        payload = {"tool": tool, "actor": actor, "session_id": session_id, "exp": exp}
        body = _b64(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        sig = _b64(hmac.new(self._key, body.encode("ascii"), hashlib.sha256).digest())
        return f"{body}.{sig}"

    def verify(self, token: str, *, now: float | None = None) -> dict | None:
        """校验签名 + 未过期;通过返回 payload,否则 None(篡改/过期/格式错一律 None)。"""
        try:
            body, sig = token.split(".", 1)
        except ValueError:
            return None
        expected = _b64(hmac.new(self._key, body.encode("ascii"), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):  # 恒定时比较,防时序侧信道
            return None
        try:
            payload = json.loads(_unb64(body))
        except (ValueError, json.JSONDecodeError):
            return None
        if not isinstance(payload, dict):
            return None
        exp = payload.get("exp")
        if not isinstance(exp, (int, float)) or (now if now is not None else time.time()) > exp:
            return None
        return payload


@dataclass(slots=True)
class UndoRecord:
    tool_name: str
    actor: str
    session_id: str
    requires: tuple[str, ...]
    undo_args: dict
    label: str
    used: bool = False


@dataclass(slots=True)
class UndoStore:
    """已执行写操作的撤销句柄(进程内,一次性)。SQLite 落库时以等价表替换,接口不变。"""

    _records: dict[str, UndoRecord] = field(default_factory=dict)

    def put(self, record: UndoRecord) -> str:
        action_id = uuid.uuid4().hex
        self._records[action_id] = record
        return action_id

    def get(self, action_id: str) -> UndoRecord | None:
        return self._records.get(action_id)

    def mark_used(self, action_id: str) -> None:
        rec = self._records.get(action_id)
        if rec is not None:
            rec.used = True


@dataclass(slots=True)
class ConfirmResult:
    ok: bool
    summary: str
    action_id: str | None = None
    reversible: bool = False
    undo_preview: str = ""
    error: str | None = None
    denied: bool = False  # 越权/主体不符 → 由路由映射 403


@dataclass(slots=True)
class ProposalResult:
    """一个已通过助手操作 RBAC 校验、可交给现有确认端点的写操作提案。"""

    ok: bool
    summary: str
    tool: AssistantTool | None = None
    action_token: str = ""
    before: dict = field(default_factory=dict)
    error: str | None = None
    denied: bool = False


@dataclass(slots=True)
class UndoResult:
    ok: bool
    summary: str
    error: str | None = None
    denied: bool = False


def _missing_required(parameters: dict, args: dict) -> list[str]:
    req = parameters.get("required") if isinstance(parameters, dict) else None
    if not isinstance(req, list):
        return []
    return [k for k in req if k not in args]


class AssistantActuator:
    def __init__(
        self,
        registry: OperationRegistry,
        services: AssistantServices,
        signer: ActionTokenSigner,
        undo_store: UndoStore,
    ) -> None:
        self._registry = registry
        self._services = services
        self._signer = signer
        self._undo = undo_store

    async def propose(
        self, tool_name: str, args: dict, principal: Any, session_id: str
    ) -> ProposalResult:
        """签发 write 操作的确认令牌，供非对话控制台入口复用同一人闸。"""
        tool = self._registry.get(tool_name)
        if tool is None or tool.kind != "write" or tool.handler is None:
            return ProposalResult(
                ok=False, summary="该工具不存在或不可作为写操作提案。", error="bad_tool"
            )
        if not tool.visible_to(principal):
            return ProposalResult(
                ok=False, summary=f"无权限执行「{tool.label}」。", denied=True, error="forbidden"
            )
        missing = _missing_required(tool.parameters, args)
        if missing:
            return ProposalResult(
                ok=False, summary=f"参数缺失:{', '.join(missing)}。", error="missing_args"
            )

        before: dict = {}
        if tool.before_handler is not None:
            try:
                snapshot = await tool.before_handler(args, principal, self._services)
                before = snapshot.data if isinstance(snapshot.data, dict) else {}
            except Exception:  # noqa: BLE001 -- 预览失败不应阻断尚未执行的提案
                before = {}
        return ProposalResult(
            ok=True,
            summary=f"已生成「{tool.label}」待确认提案，尚未执行。",
            tool=tool,
            action_token=self._signer.issue(
                tool=tool.name,
                actor=getattr(principal, "username", ""),
                session_id=session_id,
            ),
            before=before,
        )

    async def confirm(self, action_token: str, edited_args: dict, principal: Any) -> ConfirmResult:
        payload = self._signer.verify(action_token)
        if payload is None:
            return ConfirmResult(
                ok=False, summary="令牌无效或已过期,请重新发起提案。", error="bad_token"
            )
        tool = self._registry.get(str(payload.get("tool") or ""))
        if tool is None or tool.kind != "write" or tool.handler is None:
            return ConfirmResult(
                ok=False, summary="该提案对应的工具不存在或非写操作。", error="bad_tool"
            )
        # 主体绑定:令牌签发给谁就只能谁确认(防转交越权)。
        if str(payload.get("actor")) != getattr(principal, "username", None):
            return ConfirmResult(
                ok=False, summary="令牌主体与当前用户不符。", denied=True, error="actor"
            )
        session_id = payload.get("session_id")
        if not isinstance(session_id, str) or not session_id:
            return ConfirmResult(
                ok=False, summary="令牌缺少受控会话信息,请重新发起提案。", error="bad_token"
            )
        # 纵深 RBAC:执行点按 visible_to 复校(组织级权限 或 团队负责人平权;不靠提案自觉)。
        # 团队负责人的**目标范围**(只能管本团队子树)由 handler 内部再校验,返回业务级拒绝。
        if not tool.visible_to(principal):
            return ConfirmResult(
                ok=False, summary=f"无权限执行「{tool.label}」。", denied=True, error="forbidden"
            )
        args = dict(edited_args or {})
        # call_tool 的最终工具闸门审计必须跟随令牌中的服务端会话，不能让可编辑卡片改写。
        if tool.name == "call_tool":
            args["session_id"] = session_id
        missing = _missing_required(tool.parameters, args)
        if missing:
            return ConfirmResult(
                ok=False, summary=f"参数缺失:{', '.join(missing)}。", error="missing_args"
            )

        try:
            res = await tool.handler(args, principal, self._services)
        except Exception as exc:  # noqa: BLE001 —— 执行失败不 500,如实回报
            await self._audit_acted(session_id, principal, tool, args, ok=False, action_id=None)
            return ConfirmResult(ok=False, summary=f"执行「{tool.label}」失败:{exc}", error="exec")

        action_id: str | None = None
        if res.ok and tool.reversible and tool.undo_handler is not None and res.undo is not None:
            action_id = self._undo.put(
                UndoRecord(
                    tool_name=tool.name,
                    actor=getattr(principal, "username", ""),
                    session_id=session_id,
                    requires=tool.requires,
                    undo_args=res.undo,
                    label=tool.label,
                )
            )
        await self._audit_acted(session_id, principal, tool, args, ok=res.ok, action_id=action_id)
        return ConfirmResult(
            ok=res.ok,
            summary=res.summary,
            action_id=action_id,
            reversible=action_id is not None,
            undo_preview=(f"撤销将{tool.inverse}" if tool.inverse else ""),
            error=res.error,
        )

    async def undo(self, action_id: str, principal: Any) -> UndoResult:
        rec = self._undo.get(action_id)
        if rec is None:
            return UndoResult(ok=False, summary="撤销句柄不存在。", error="not_found")
        if rec.used:
            return UndoResult(ok=False, summary="该操作已被撤销过(撤销一次性)。", error="used")
        tool = self._registry.get(rec.tool_name)
        if tool is None or tool.undo_handler is None:
            return UndoResult(ok=False, summary="对应工具无撤销执行器。", error="no_undo")
        # 撤销与原写操作同权(plan §4.6):按工具 visible_to 复校(含团队负责人平权)。
        if not tool.visible_to(principal):
            return UndoResult(
                ok=False, summary=f"无权限撤销「{rec.label}」。", denied=True, error="forbidden"
            )
        try:
            res = await tool.undo_handler(rec.undo_args, principal, self._services)
        except Exception as exc:  # noqa: BLE001
            return UndoResult(ok=False, summary=f"撤销「{rec.label}」失败:{exc}", error="exec")
        self._undo.mark_used(action_id)
        await self._audit_undone(rec.session_id, principal, rec, res.summary)
        return UndoResult(ok=res.ok, summary=res.summary)

    async def _audit_acted(
        self,
        session_id: str,
        principal: Any,
        tool: AssistantTool,
        args: dict,
        *,
        ok: bool,
        action_id: str | None,
    ) -> None:
        await self._services.pipeline.audit.append(
            AuditEvent(
                session_id=session_id,
                event_type=AuditEventType.ASSISTANT_ACTED,
                subject_id=tool.name,
                evidence={
                    "actor": getattr(principal, "username", ""),
                    "tool": tool.name,
                    "args": redact(json.dumps(args, ensure_ascii=False, default=str)[:200]),
                    "ok": ok,
                    "action_id": action_id,
                    "reversible": action_id is not None,
                },
            )
        )

    async def _audit_undone(
        self, session_id: str, principal: Any, rec: UndoRecord, summary: str
    ) -> None:
        await self._services.pipeline.audit.append(
            AuditEvent(
                session_id=session_id,
                event_type=AuditEventType.ASSISTANT_UNDONE,
                subject_id=rec.tool_name,
                evidence={
                    "actor": getattr(principal, "username", ""),
                    "tool": rec.tool_name,
                    "result": redact(summary[:200]),
                },
            )
        )
