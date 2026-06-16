"""企业智能体 Web 服务 —— 模拟"被保护的企业系统"对外暴露的智能体接口。

枢衡网关把(已放行的)用户请求转发到这里。本服务**不含任何安全管控**。

启动:  uv run python -m fulcrum.enterprise   (默认 http://127.0.0.1:8800)
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI

from ..demo import gov
from .agent import EnterpriseAgent


def create_enterprise_app() -> FastAPI:
    app = FastAPI(title="企业政务智能体(被保护方)")
    agent = EnterpriseAgent()

    @app.get("/")
    def index() -> dict[str, Any]:
        return {
            "name": "企业政务大厅智能体",
            "protected_by": "未接入安全网关时直连即裸奔;请经枢衡网关访问",
            "endpoints": ["POST /chat", "GET /tools", "GET /healthz"],
        }

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/tools")
    def tools() -> dict[str, Any]:
        return {"tools": gov.TOOL_SCHEMAS, "docs": gov.DOCS}

    @app.post("/chat")
    async def chat(body: dict) -> dict[str, Any]:
        return await agent.run_turn(str(body.get("session_id", "s")), str(body.get("message", "")))

    @app.post("/reset")
    def reset(body: dict) -> dict[str, bool]:
        agent.reset(str(body.get("session_id", "s")))
        return {"ok": True}

    return app


app = create_enterprise_app()


if __name__ == "__main__":
    import uvicorn

    print("企业政务智能体(被保护方):http://127.0.0.1:8800")
    uvicorn.run(app, host="127.0.0.1", port=8800, log_level="warning")
