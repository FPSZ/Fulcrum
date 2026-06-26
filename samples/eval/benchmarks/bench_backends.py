"""模型后端注册表 —— 把模型名解析成统一 env(LLM_BASE/LLM_MODEL/LLM_API_KEY/LLM_NO_THINK)。

供 `run_suite.py` 跨模型编排:本地模型(llama-server,可选自启)、MiMo(.env 云端)、
DeepSeek(环境变量 DEEPSEEK_API_KEY,**不硬编码密钥**)。新增模型在 _LOCAL_GGUF / env_for 补一行。
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, "src")
from fulcrum.config import Settings  # noqa: E402

# 本地推理服务(单实例单模型;model 字段被 llama-server 忽略,仅作标签)。
LOCAL_PORT = os.environ.get("BENCH_LOCAL_PORT", "8123")
LOCAL_BASE = f"http://127.0.0.1:{LOCAL_PORT}/v1"
# 自启 llama-server 用(--serve);路径可经 env 覆盖。新增本地模型在此登记。
LLAMA_EXE = os.environ.get(
    "BENCH_LLAMA_EXE", r"D:\AI\Local\bin\llama-server-hip\llama-server.exe"
)
_LOCAL_GGUF: dict[str, str] = {
    "qwen3-8b": r"D:\AI\Local\Models\Qwen\Qwen3-8B-Q4_K_M.gguf",
    "qwen3-14b": r"D:\AI\Local\Models\Qwen\Qwen3-14B-Q4_K_M.gguf",
    "qwen3-35b": r"D:\AI\Local\Models\Qwen\Qwen3.6-35B-A3B-Q8_0.gguf",
}

# 全部已知模型(--models all 用);本地在前、云端在后。
ALL_MODELS: list[str] = [*_LOCAL_GGUF, "mimo", "deepseek"]


def is_local(name: str) -> bool:
    return name in _LOCAL_GGUF or name == "local"


def gguf(name: str) -> str | None:
    return _LOCAL_GGUF.get(name)


def env_for(name: str) -> dict[str, str] | None:
    """该模型的统一 env;None = 未配置(缺密钥/端点),编排器跳过并说明。"""
    s = Settings()
    if is_local(name):
        # 本地自托管,数据不出域;Qwen3 等推理模型默认关思考(直出裁决/工具调用)。
        return {"LLM_BASE": LOCAL_BASE, "LLM_MODEL": name, "LLM_API_KEY": "", "LLM_NO_THINK": "1"}
    if name == "mimo":
        # 复用 .env 的 FULCRUM_MODEL_*(创作者云端);须为真云端点、有密钥。
        if not s.model_api_key or any(h in s.model_endpoint for h in ("127.0.0.1", "localhost")):
            return None
        # 创作者额度对高频限流(连发→空返/超时),agentic 套件限速 1s/条;可经 BENCH_MIMO_SLEEP 调。
        return {
            "LLM_BASE": s.model_endpoint, "LLM_MODEL": s.model_name,
            "LLM_API_KEY": s.model_api_key, "LLM_NO_THINK": "1",
            "GOV_SLEEP": os.environ.get("BENCH_MIMO_SLEEP", "1.0"),
        }
    if name == "deepseek":
        key = os.environ.get("DEEPSEEK_API_KEY", "").strip()
        if not key:
            return None
        # deepseek-chat 非推理模型,不关思考。
        return {
            "LLM_BASE": "https://api.deepseek.com/v1", "LLM_MODEL": "deepseek-chat",
            "LLM_API_KEY": key, "LLM_NO_THINK": "0",
        }
    return None


def skip_reason(name: str) -> str:
    if name == "mimo":
        return "未配置 .env 的 FULCRUM_MODEL_*(云端点+密钥)"
    if name == "deepseek":
        return "未设环境变量 DEEPSEEK_API_KEY"
    return "未知模型"
