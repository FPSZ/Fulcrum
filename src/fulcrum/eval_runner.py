"""控制台「发起评测」的组装层 runner —— 在请求里触发离线评测,把产物写回 `eval_report_path`。

评测纯检测回放(不调模型),200 条样例 ~0.1s。但 `run_and_write` 内部用 `asyncio.run`,不能在
事件循环线程里直接调,且回放是 CPU 密集——故经 `asyncio.to_thread` 丢到线程池跑,既复用 CLI 同一
出分函数(口径一致),又不阻塞 FastAPI 事件循环。`asyncio.Lock` 串行化,防重复点击并发跑。

置于组装层(同 `live_feed.py`):它同时依赖 `fulcrum.eval` 与 `build_pipeline`,放 adapters 会回指
组装根成环;adapters 侧的评测路由只认 `EvalRunnerLike` 协议、由 `create_app` 注入本类实例。
"""

from __future__ import annotations

import asyncio
from typing import Any


class EvalRunner:
    """触发一次评测并把报告落到 `report_path`;`run()` 返回报告 dict,`running` 标识进行中。"""

    def __init__(self, report_path: str, dataset: str, policy: str) -> None:
        self._report_path = report_path
        self._dataset = dataset
        self._policy = policy
        self._lock = asyncio.Lock()

    @property
    def running(self) -> bool:
        return self._lock.locked()

    async def run(self) -> dict[str, Any]:
        """跑一次评测(线程池,不阻塞事件循环),写产物并返回报告 dict。并发调用会排队串行。"""
        async with self._lock:
            from .eval.__main__ import run_and_write

            return await asyncio.to_thread(
                run_and_write, self._dataset, self._policy, self._report_path
            )
