"""AI 操作助手 · 规划大脑(把自然语言意图映射成一个受治理的动作)。

纯编排 + 可注入模型后端:`plan()` 用 LLM 从动作目录里选一个动作并填参数,然后**后端强制**
RBAC(动作 `requires` ⊆ 操作员权限,越权直接拒绝并说明)与风险分级(高危标记二次确认)。
模型后端 `complete(prompt)->str` 可注入(测试用确定性假后端,无需真 LLM);默认实现 = 同步调
OpenAI 兼容端点(经 .env,如 DeepSeek/MiMo),解析 JSON 裁决。

安全:这是"会按钮的副驾"的大脑——它只**规划**动作(选哪个 + 是否准许),不执行 UI 操作;
高危动作的真正执行仍要前端二次确认 + 命中各自的 RBAC 守卫端点(纵深,不靠助手自觉)。
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from .catalog import DEFAULT_CATALOG, RISK_HIGH, Action

_LOG = logging.getLogger(__name__)

# 模型后端契约:(prompt) -> 模型文本输出(应为一段 JSON)。失败应返回 "" 而非抛错。
ModelComplete = Callable[[str], Awaitable[str]]

_SYSTEM = (
    "你是政企安全控制台的操作副驾。把【操作员意图】映射到下面【可用动作】之一并给出参数。\n"
    "只能从列表里选,**不得发明动作**;无法对应任何动作就让 action_id 为 null。\n"
    "只输出一个 JSON,不要多余文字:"
    '{"action_id": "动作id 或 null", "args": {参数对象}, "reason": "一句中文说明为什么这么选"}'
)


@dataclass(slots=True)
class AssistantPlan:
    ok: bool  # 是否成功规划出一个准许执行的动作
    reason: str  # 给操作员看的说明
    action_id: str | None = None
    label: str = ""
    args: dict = field(default_factory=dict)
    risk: str = ""
    requires_confirmation: bool = False  # 高危 → 前端须二次确认
    denied: bool = False  # 越权 / 被闸门拒


def _format_catalog(catalog: tuple[Action, ...]) -> str:
    lines = []
    for a in catalog:
        hint = f"(参数:{a.args_hint})" if a.args_hint else ""
        lines.append(f"- {a.id}:{a.label} —— {a.description}{hint}")
    return "\n".join(lines)


def _parse(text: str) -> dict | None:
    """从模型输出里容错抽取第一个 JSON 对象;失败返回 None。"""
    if not text:
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        pass
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
        return obj if isinstance(obj, dict) else None
    except (ValueError, TypeError):
        return None


async def plan(
    intent: str,
    permissions: frozenset[str] | set[str],
    complete: ModelComplete,
    catalog: tuple[Action, ...] = DEFAULT_CATALOG,
) -> AssistantPlan:
    """自然语言意图 → 受治理的动作规划。RBAC/风险在此**强制**,不依赖前端。"""
    by_id = {a.id: a for a in catalog}
    prompt = (
        f"{_SYSTEM}\n\n【可用动作】\n{_format_catalog(catalog)}\n\n【操作员意图】\n{intent.strip()}"
    )

    try:
        raw = await complete(prompt)
    except Exception as exc:  # noqa: BLE001 —— 模型不可达 → 优雅降级,不让助手 500
        _LOG.warning("assistant 模型后端异常:%s", exc)
        raw = ""

    parsed = _parse(raw)
    if not parsed or not parsed.get("action_id"):
        reason = (parsed or {}).get(
            "reason"
        ) or "未能把你的意图对应到可执行动作,请换种说法或更具体些。"
        return AssistantPlan(ok=False, reason=str(reason))

    action_id = str(parsed["action_id"])
    action = by_id.get(action_id)
    if action is None:
        return AssistantPlan(ok=False, reason=f"模型选择了未知动作「{action_id}」,已忽略。")

    # RBAC 强制:动作所需权限点必须全在操作员权限内,否则越权拒绝并说明缺哪个。
    missing = [p for p in action.requires if p not in permissions]
    if missing:
        return AssistantPlan(
            ok=False,
            denied=True,
            action_id=action_id,
            label=action.label,
            risk=action.risk,
            reason=f"无权限执行「{action.label}」:你的角色缺少 {', '.join(missing)}。",
        )

    raw_args = parsed.get("args")
    args = raw_args if isinstance(raw_args, dict) else {}
    return AssistantPlan(
        ok=True,
        action_id=action_id,
        label=action.label,
        args=args,
        risk=action.risk,
        requires_confirmation=action.risk == RISK_HIGH,
        reason=str(parsed.get("reason") or action.label),
    )


def make_model_backend(
    endpoint: str, api_key: str, model: str, timeout: float = 20.0
) -> ModelComplete:
    """默认模型后端:异步调 OpenAI 兼容 /chat/completions,取 content。失败返回 ""(不抛)。"""

    async def complete(prompt: str) -> str:
        import httpx

        url = endpoint.rstrip("/") + "/chat/completions"
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0,
        }
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(url, json=payload, headers=headers)
                resp.raise_for_status()
                return str(resp.json()["choices"][0]["message"]["content"] or "")
        except Exception as exc:  # noqa: BLE001 —— 端点不可达/未配置 → 空串,plan 据此回"模型不可用"
            _LOG.warning("assistant 模型调用失败:%s", exc)
            return ""

    return complete
