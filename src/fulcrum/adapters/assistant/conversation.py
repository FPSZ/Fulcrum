"""ConversationStore —— 操作助手的多轮对话记忆(落盘 + 自动压缩)。

后端 Agent 本身无状态:每轮只看 system + 当轮意图。要"像个真 Agent"地延续上下文,就得把
每个 `session_id` 的对话脱机存起来,下一轮带着历史一起推。本存储:

  • 落盘:一会话一文件(data/runtime/conversations/<hash>.json,gitignore),进程重启不丢;
  • 记忆体:OpenAI 线格式 transcript(user/assistant/tool 轮;**不含** system,运行时再前置);
  • 自动压缩(防上下文爆):
      ① 每次保存先把超长的工具返回(read 的大段 dump)截断到上限,先掐住最猛的增长源;
      ② 总字数超阈值时,按"用户轮"边界切,保留最近 keep_turns 轮原文,更早的轮用一次模型调用
         压成「早前对话摘要」,以 user→assistant 合成对替换——既缩长度又不丢上下文,且保持
         角色交替合法(assistant tool_calls 与其 tool 结果始终成对留在被保留轮内,不会切坏)。

口径用字符数估算(无分词器,中文 1 字≈1–2 token,够用且零依赖)。摘要失败软降级为朴素截断,
绝不因压缩失败而抛错中断对话(fail-safe)。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import tempfile
from collections import defaultdict
from collections.abc import Awaitable, Callable
from pathlib import Path

_LOG = logging.getLogger(__name__)

# 摘要器契约:把一段对话文本压成简洁中文要点。失败应返回空串(由调用方软降级)。
Summarizer = Callable[[str], Awaitable[str]]

_SUMMARY_PREFIX = "【系统·早前对话摘要】\n"
_SUMMARY_ACK = "好的,我已记住以上对话要点,继续。"
_TRUNC_MARK = "…(内容过长已截断)"


def _chars(messages: list[dict]) -> int:
    return sum(len(str(m.get("content") or "")) for m in messages)


class ConversationStore:
    """按 session_id 持久化对话 transcript,并在超长时自动压缩。"""

    def __init__(
        self,
        directory: str,
        *,
        max_chars: int = 12_000,
        keep_turns: int = 6,
        max_tool_chars: int = 1_500,
    ) -> None:
        self._dir = Path(directory)
        self._max_chars = max_chars
        self._keep_turns = keep_turns
        self._max_tool_chars = max_tool_chars
        self._locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    # ── 持久化 ────────────────────────────────────────────────────────────
    def _path(self, session_id: str) -> Path:
        # session_id 含 ":" 等不宜入文件名的字符 → 取 sha256 短哈希做文件名,原 id 存进 JSON。
        h = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:32]
        return self._dir / f"{h}.json"

    def load(self, session_id: str) -> list[dict]:
        """读取某会话的历史 transcript(不含 system);无则空。坏文件视为空,不抛。"""
        path = self._path(session_id)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            msgs = raw.get("messages")
            return msgs if isinstance(msgs, list) else []
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return []

    def save(self, session_id: str, messages: list[dict]) -> None:
        """原子落盘(mkstemp + os.replace),与各 store 同一套写法。空对话不建文件。"""
        if not messages:
            return
        self._dir.mkdir(parents=True, exist_ok=True)
        path = self._path(session_id)
        payload = json.dumps(
            {"session_id": session_id, "messages": messages},
            ensure_ascii=False,
        )
        fd, tmp = tempfile.mkstemp(dir=self._dir, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(payload)
            os.replace(tmp, path)
        except OSError as exc:  # noqa: BLE001 —— 落盘失败不挡对话(退化为本轮无记忆)
            _LOG.warning("对话落盘失败 %s:%s", session_id, exc)
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def reset(self, session_id: str) -> None:
        """清空某会话记忆(新建会话 / 显式清除)。"""
        try:
            self._path(session_id).unlink()
        except (FileNotFoundError, OSError):
            pass

    def lock(self, session_id: str) -> asyncio.Lock:
        """同会话的并发请求串行化(防同时读改写互相覆盖)。"""
        return self._locks[session_id]

    # ── 压缩 ──────────────────────────────────────────────────────────────
    def _truncate_tools(self, messages: list[dict]) -> list[dict]:
        """把超长的工具返回截断到上限——增长最猛的来源,先掐住。"""
        out: list[dict] = []
        for m in messages:
            if m.get("role") == "tool":
                content = str(m.get("content") or "")
                if len(content) > self._max_tool_chars:
                    m = {**m, "content": content[: self._max_tool_chars] + _TRUNC_MARK}
            out.append(m)
        return out

    @staticmethod
    def _split_turns(messages: list[dict]) -> list[list[dict]]:
        """按 'user' 边界切成"轮"——每轮含其后的 assistant/tool,保证成对不切坏。"""
        turns: list[list[dict]] = []
        cur: list[dict] = []
        for m in messages:
            if m.get("role") == "user" and cur:
                turns.append(cur)
                cur = []
            cur.append(m)
        if cur:
            turns.append(cur)
        return turns

    @staticmethod
    def _render(turns: list[list[dict]]) -> str:
        """把待压缩的旧轮渲染成可读文本,喂给摘要器。"""
        lines: list[str] = []
        role_cn = {"user": "操作员", "assistant": "助手", "tool": "工具返回"}
        for turn in turns:
            for m in turn:
                role = role_cn.get(str(m.get("role")), str(m.get("role")))
                content = str(m.get("content") or "").strip()
                calls = m.get("tool_calls") or []
                if calls:
                    names = ", ".join(c.get("function", {}).get("name", "?") for c in calls)
                    content = (content + f" [调用工具:{names}]").strip()
                if content:
                    lines.append(f"{role}:{content}")
        return "\n".join(lines)

    async def compress_if_needed(
        self, messages: list[dict], summarizer: Summarizer
    ) -> tuple[list[dict], bool]:
        """超阈值则把更早的轮压成摘要,返回(新 transcript, 是否压缩过)。"""
        messages = self._truncate_tools(messages)
        if _chars(messages) <= self._max_chars:
            return messages, False

        turns = self._split_turns(messages)
        if len(turns) <= self._keep_turns:
            # 轮数不够压(可能单轮过大)——工具已截断,尽力而为不再动。
            return messages, False

        old, keep = turns[: -self._keep_turns], turns[-self._keep_turns :]
        rendered = self._render(old)
        try:
            summary = (await summarizer(rendered)).strip()
        except Exception as exc:  # noqa: BLE001 —— 摘要失败软降级
            _LOG.warning("对话摘要失败:%s", exc)
            summary = ""
        if not summary:  # 朴素降级:留旧文开头,绝不空手丢上下文
            summary = rendered[:500].strip() + ("…" if len(rendered) > 500 else "")

        head = [
            {"role": "user", "content": _SUMMARY_PREFIX + summary},
            {"role": "assistant", "content": _SUMMARY_ACK},
        ]
        kept = [m for turn in keep for m in turn]
        return head + kept, True
