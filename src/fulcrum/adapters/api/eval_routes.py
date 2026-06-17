"""评测验证路由 —— 只读暴露 `python -m fulcrum.eval` 的最近一次报告,经 eval.view 鉴权。

评测是**离线流程**(CLI 回放样例出分,产物写 `eval_report_path`),本端点只把最近报告
读出来给评测页展示,不在请求里跑评测。报告缺失 / 损坏 → 返回 null(评测页回退演示 seed),
不抛 500 —— "还没跑过评测"是正常状态,不是错误。
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import Depends, FastAPI
from pydantic import ValidationError

from ..auth import Principal
from .deps import AuthDeps
from .schemas import EvalReportDTO


def load_report(path: str | Path) -> EvalReportDTO | None:
    """读并校验评测报告;文件缺失 / 非法 JSON / 不符 schema 一律视为「尚无报告」→ None。"""
    p = Path(path)
    if not p.is_file():
        return None
    try:
        return EvalReportDTO.model_validate(json.loads(p.read_text(encoding="utf-8")))
    except (OSError, ValueError, ValidationError):
        return None


def register_eval_routes(app: FastAPI, report_path: str, deps: AuthDeps) -> None:
    can_view = deps.require("eval.view")

    @app.get("/eval/report", response_model=EvalReportDTO | None)
    async def eval_report(_: Principal = Depends(can_view)) -> EvalReportDTO | None:
        return load_report(report_path)
