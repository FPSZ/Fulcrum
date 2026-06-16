"""政务智能体安全沙盘 · Web 服务 —— 给评委看的可交互演示。

启动:  uv run python -m fulcrum.demo.server   (默认 http://127.0.0.1:8800)
依赖:  .env 内 FULCRUM_MODEL_*(MiMo)。本服务独立于主控制台与登录鉴权,互不影响。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import FileResponse

from . import gov
from .runtime import GovRuntime

_STATIC = Path(__file__).parent / "static"


def create_demo_app() -> FastAPI:
    app = FastAPI(title="枢衡 · 政务智能体安全沙盘")
    rt = GovRuntime()

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(_STATIC / "index.html")

    @app.get("/api/files")
    def files() -> dict[str, Any]:
        return {"docs": gov.DOCS}

    @app.post("/api/chat")
    async def chat(body: dict) -> dict[str, Any]:
        return await rt.run_turn(str(body.get("session_id", "s")), str(body.get("message", "")))

    @app.post("/api/tool")
    async def tool(body: dict) -> dict[str, Any]:
        """红队直连:不经模型,直接把一个高危工具调用送进枢衡闸门。"""
        return await rt.gate_direct(
            str(body.get("session_id", "s")),
            str(body.get("tool", "")),
            dict(body.get("args") or {}),
        )

    @app.post("/api/reset")
    def reset(body: dict) -> dict[str, Any]:
        rt.reset(str(body.get("session_id", "s")))
        return {"ok": True}

    return app


app = create_demo_app()


if __name__ == "__main__":
    import uvicorn

    print("枢衡政务安全沙盘:打开 http://127.0.0.1:8800")
    uvicorn.run(app, host="127.0.0.1", port=8800, log_level="warning")
