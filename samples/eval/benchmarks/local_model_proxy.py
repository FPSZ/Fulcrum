"""本地模型代理 —— 把 localhost:PORT/v1 转发到 .env 的真模型(MiMo),供只认 localhost 的基准工具
(AgentDojo `--model LOCAL/VLLM_PARSED`)用远程 MiMo 当后端。

一处解决三件事:①端点(远程→localhost);②鉴权(注入 Bearer);③关思考(MiMo 推理模型作 agent
后端必须 `chat_template_kwargs.enable_thinking=false`,否则慢且 content 空)+ 补 max_tokens 下限。

读 .env 的 FULCRUM_MODEL_*(端点/密钥/模型名)。
用法:python samples/eval/benchmarks/local_model_proxy.py [port]
"""

from __future__ import annotations

import sys

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

sys.path.insert(0, "src")
from fulcrum.config import Settings  # noqa: E402

_S = Settings()
_TARGET = _S.model_endpoint.rstrip("/")
_KEY = _S.model_api_key
_MODEL = _S.model_name

app = FastAPI()


@app.get("/v1/models")
async def models() -> dict:
    return {"object": "list", "data": [{"id": _MODEL, "object": "model", "owned_by": "local"}]}


@app.post("/v1/chat/completions")
async def chat(req: Request) -> JSONResponse:
    body = await req.json()
    body["model"] = _MODEL  # 强制真模型名(客户端可能用 /v1/models 之外的别名)
    ctk = dict(body.get("chat_template_kwargs") or {})
    ctk["enable_thinking"] = False  # 关思考(推理模型作内联 agent 后端)
    body["chat_template_kwargs"] = ctk
    if int(body.get("max_tokens") or 0) < 256:
        body["max_tokens"] = 1024  # 防裁决/工具调用被推理预算截断
    async with httpx.AsyncClient(timeout=180) as c:
        r = await c.post(
            _TARGET + "/chat/completions", json=body, headers={"Authorization": f"Bearer {_KEY}"}
        )
    try:
        return JSONResponse(status_code=r.status_code, content=r.json())
    except Exception:
        return JSONResponse(status_code=502, content={"error": r.text[:500]})


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    print(f"代理 localhost:{port}/v1 → {_TARGET} (model={_MODEL}, 关思考)")
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
