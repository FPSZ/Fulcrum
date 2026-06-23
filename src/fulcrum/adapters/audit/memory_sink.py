"""InMemoryAuditSink —— append-only + **版本化** hash-chain 审计(内存桩)。

哈希链口径(canonical / event_hash / 断点定位)由 `hashchain` 模块统一提供,与 SQLite
持久化 sink **共用同一份实现**,杜绝两套 sink 算出互不可验证的链。本文件只管"内存里
怎么存这些链 + 跨会话聚合读",落库版本见 `sqlite_sink`(接口一致)。
"""

from __future__ import annotations

from ...core.domain import AuditEvent
from ...core.registry import capability
from .hashchain import GENESIS, locate_break, seal


@capability("audit", "memory")
class InMemoryAuditSink:
    def __init__(self) -> None:
        self._chains: dict[str, list[AuditEvent]] = {}

    # async:与 AuditSink 端口一致(内存桩无真实 IO,故体内无 await;SQLite 实现将有)。
    async def append(self, event: AuditEvent) -> AuditEvent:
        chain = self._chains.setdefault(event.session_id, [])
        prev_hash = chain[-1].event_hash if chain else GENESIS
        seal(event, index=len(chain), prev_hash=prev_hash)  # 未知版本 → AuditError 上抛(写入不降级)
        chain.append(event)
        return event

    async def events(self, session_id: str) -> list[AuditEvent]:
        return list(self._chains.get(session_id, []))

    # ── 聚合读取(供总览/事件/工具/审计列表跨会话汇总)──────────────────
    # 这两个是 AuditSink 端口契约的一部分(端口除 per-session 读外亦暴露跨会话聚合);
    # 内存实现直接遍历 dict,SQLite 实现以一条聚合查询提供等价能力,调用方不再按
    # 具体类窄化(此前 `isinstance(InMemoryAuditSink)` 硬闸已拆,见各 *_routes)。
    def session_ids(self) -> list[str]:
        return list(self._chains.keys())

    def all_events(self) -> list[AuditEvent]:
        return [event for chain in self._chains.values() for event in chain]

    def prune_to_recent(self, max_sessions: int) -> None:
        """限长:仅保留最近写入的 max_sessions 个会话链,丢弃更早的。

        供长跑的实时流量驱动控内存——dict 保留插入序,最早的键在前,从前弹出至不超上限。
        纯演示能力(非端口契约);持久化实现以「按 created_at 限窗查询」提供等价上界。
        """
        while len(self._chains) > max_sessions:
            del self._chains[next(iter(self._chains))]

    async def verify_chain(self, session_id: str) -> bool:
        return locate_break(self._chains.get(session_id, [])) is None

    async def locate_break(self, session_id: str) -> int | None:
        """定位审计链中第一处断裂的事件位置(防篡改取证);完好返回 None。逻辑见 hashchain。"""
        return locate_break(self._chains.get(session_id, []))
