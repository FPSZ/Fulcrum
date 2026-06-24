"""评测验证路由 —— 读最近一次评测报告(eval.view),并支持从控制台**发起评测**(eval.run)。

- ``GET /eval/report``:把最近报告读出来给评测页展示;缺失/损坏 → null(回退演示 seed),不抛 500。
- ``POST /eval/run``(eval.run):在请求里触发一次离线评测(纯检测回放 ~0.1s,经组装层 `EvalRunner`
  丢线程池跑,与 CLI 同一出分函数),写回 `eval_report_path` 并**直接返回新报告**;补孤儿权限 `eval.run`
  (此前声明却无端点 —— 评测只能 CLI 跑)。进行中再次发起 → 409。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol

from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import ValidationError

from ..auth import Principal
from .deps import AuthDeps
from .schemas import EvalReportDTO


class EvalRunnerLike(Protocol):
    """评测触发器协议(组装层 `EvalRunner` 实现);路由只认协议,不依赖组装根(不破边界)。"""

    @property
    def running(self) -> bool: ...

    async def run(self) -> dict: ...


def load_report(path: str | Path) -> EvalReportDTO | None:
    """读并校验评测报告;文件缺失 / 非法 JSON / 不符 schema 一律视为「尚无报告」→ None。"""
    p = Path(path)
    if not p.is_file():
        return None
    try:
        return EvalReportDTO.model_validate(json.loads(p.read_text(encoding="utf-8")))
    except (OSError, ValueError, ValidationError):
        return None


def register_eval_routes(
    app: FastAPI, report_path: str, runner: EvalRunnerLike | None, deps: AuthDeps
) -> None:
    can_view = deps.require("eval.view")
    can_run = deps.require("eval.run")  # 发起评测是写操作(产生新产物),单独鉴权

    @app.get("/eval/report", response_model=EvalReportDTO | None)
    async def eval_report(_: Principal = Depends(can_view)) -> EvalReportDTO | None:
        return load_report(report_path)

    @app.post("/eval/run", response_model=EvalReportDTO | None)
    async def run_eval(_: Principal = Depends(can_run)) -> EvalReportDTO | None:
        if runner is None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="评测触发器未装配")
        if runner.running:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="评测进行中,请稍候")
        await runner.run()  # 写回 report_path(线程池跑,不阻塞事件循环)
        return load_report(report_path)  # 复用读路径校验,返回与 GET 同结构
