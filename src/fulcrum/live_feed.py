"""实时流量驱动 —— 把攻击语料库按节奏喂进运行中的管线,让控制台首页/事件页显示真实活动。

**仅用于演示/可视化,不改任何检测逻辑。** 新启动的实例审计为空 → 前端回退到导入的演示
seed;本驱动持续把 `samples/eval/corpus/` 的语料真跑一遍 `screen_input / evaluate_intent /
screen_output`(复用评测分发 `eval.run_sample`),产出真实 hash-chain 审计事件,落进
`/overview` · `/events` 读的**同一个内存 sink**。于是首页 KPI、实时事件页显示的是**真管线判定**
(真攻击真检测,非手写 seed),且随时间滚动。

默认关闭(`FULCRUM_LIVE_FEED_ENABLED=1` 开启),仅在内存审计 sink 下生效;长跑按
`live_feed_max_sessions` 限内存。属组装层能力(import eval/capabilities),故置于 `fulcrum.app`
同级而非 adapters 内,不违反 adapters↛capabilities 边界。
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import TYPE_CHECKING

from .adapters.audit.memory_sink import InMemoryAuditSink
from .eval.dataset import load_dataset
from .eval.runner import run_sample

if TYPE_CHECKING:
    from .core.pipeline import SecurityPipeline

_log = logging.getLogger("fulcrum.live_feed")


class LiveTrafficFeed:
    """后台任务:循环把语料样例真跑进管线,产出实时审计事件(限内存)。"""

    def __init__(
        self,
        pipeline: SecurityPipeline,
        dataset_path: str,
        interval_seconds: float = 2.0,
        max_sessions: int = 300,
    ) -> None:
        self._pipeline = pipeline
        self._dataset_path = dataset_path
        self._interval = max(0.2, interval_seconds)
        self._max_sessions = max_sessions
        self._task: asyncio.Task[None] | None = None
        self._seq = 0

    def start(self) -> None:
        """在运行中的事件循环上挂起后台驱动(uvicorn startup 调用)。"""
        if self._task is None:
            self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        """取消并回收后台驱动(uvicorn shutdown 调用)。"""
        if self._task is None:
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        self._task = None

    async def _run(self) -> None:
        try:
            samples = load_dataset(self._dataset_path)
        except Exception as exc:  # noqa: BLE001 —— 语料缺失/损坏只跳过驱动,绝不拖垮服务
            _log.warning("实时流量驱动未启动:语料加载失败(%s):%s", self._dataset_path, exc)
            return
        sink = self._pipeline.audit
        _log.info(
            "实时流量驱动启动:%d 条语料,每 %.1fs 一条,最多留 %d 会话",
            len(samples),
            self._interval,
            self._max_sessions,
        )
        order = list(range(len(samples)))
        while True:
            random.shuffle(order)  # 每轮打散,事件页滚动出多样判定而非固定序
            for i in order:
                sample = samples[i]
                self._seq += 1
                sid = f"live-{self._seq:06d}"
                try:
                    await run_sample(self._pipeline, sample, sid=sid)
                except Exception as exc:  # noqa: BLE001 —— 单条回放失败不影响后续
                    _log.debug("实时流量样例 %s 回放失败:%s", sample.sample_id, exc)
                if isinstance(sink, InMemoryAuditSink):
                    sink.prune_to_recent(self._max_sessions)
                await asyncio.sleep(self._interval)
