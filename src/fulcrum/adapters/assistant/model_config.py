"""操作助手的模型接入配置 —— 运行时可改、落盘持久化,设置页填表即生效(本地私有化优先)。

设计同 `gateway/config.py`:买家拿到镜像后在「操作助手·模型设置」里填:协议、端点、密钥、
模型名,保存即热加载(每次请求读当前配置),无需改 .env 或重启。

支持三种主流协议(各自的传输在 `model_transports.py`):
- ``openai``    —— OpenAI 兼容 /chat/completions(覆盖 OpenAI/DeepSeek/Kimi/MiMo +
                   本地 vLLM/LM Studio/llama.cpp/Ollama 的 /v1 兼容端点)
- ``ollama``    —— Ollama 原生 /api/chat(本地私有化最常见,通常免密钥)
- ``anthropic`` —— Anthropic /v1/messages(Claude)

私有化优先:本地模型(ollama / 本地 openai 兼容)往往**无需密钥**,api_key 可留空。
密钥(api_key)明文落盘(同 .env 取舍,文件收紧 0600)但**绝不原样回前端**:对外一律掩码。
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

Protocol = Literal["openai", "ollama", "anthropic"]


class AssistantModelConfig(BaseModel):
    """操作助手模型接入配置(单实例)。字段即设置页表单项。"""

    protocol: Protocol = "openai"
    # 端点 base(不含协议路径):各传输自行拼 /chat/completions、/api/chat、/v1/messages。
    endpoint: str = Field(default="", max_length=512)
    api_key: str = Field(default="", max_length=2048)  # 明文落盘,不回前端;本地模型可空
    model: str = Field(default="", max_length=128)
    timeout_seconds: float = Field(default=90.0, ge=1, le=600)
    verify_tls: bool = True
    # 操作员是否已显式完成配置:控制前端「未配置呼吸灯 + 发消息拦截」。
    configured: bool = False

    @property
    def is_ready(self) -> bool:
        """是否可真正发起调用:已标记配置完成且端点/模型齐备。"""
        return self.configured and bool(self.endpoint.strip()) and bool(self.model.strip())


def _mask(secret: str) -> str:
    if not secret:
        return ""
    return ("•" * 6 + secret[-4:]) if len(secret) > 4 else "•" * len(secret)


class AssistantModelConfigPublic(BaseModel):
    """回前端的安全视图:密钥掩码,只暴露「是否已设置」与「是否配置完成」。"""

    protocol: Protocol
    endpoint: str
    model: str
    api_key_masked: str
    api_key_set: bool
    timeout_seconds: float
    verify_tls: bool
    configured: bool
    ready: bool

    @classmethod
    def of(cls, c: AssistantModelConfig) -> AssistantModelConfigPublic:
        return cls(
            protocol=c.protocol,
            endpoint=c.endpoint,
            model=c.model,
            api_key_masked=_mask(c.api_key),
            api_key_set=bool(c.api_key),
            timeout_seconds=c.timeout_seconds,
            verify_tls=c.verify_tls,
            configured=c.configured,
            ready=c.is_ready,
        )


class AssistantModelConfigStore:
    """JSON 文件持久化(放 data/runtime,挂 Docker 卷即不丢)。低频写,文件足够;热加载靠缓存。"""

    def __init__(self, path: str, seed: AssistantModelConfig | None = None) -> None:
        self._path = Path(path)
        self._seed = seed or AssistantModelConfig()
        self._cache: AssistantModelConfig | None = None

    def load(self) -> AssistantModelConfig:
        if self._cache is not None:
            return self._cache
        if self._path.is_file():
            try:
                data = json.loads(self._path.read_text(encoding="utf-8"))
                self._cache = AssistantModelConfig.model_validate(data)
            except (json.JSONDecodeError, ValueError, OSError):
                self._cache = self._seed
        else:
            self._cache = self._seed
            self._write(self._cache)  # 首启落种子,买家看到默认表单
        return self._cache

    def save(self, cfg: AssistantModelConfig) -> AssistantModelConfig:
        self._write(cfg)
        self._cache = cfg
        return cfg

    def _write(self, cfg: AssistantModelConfig) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # 原子替换:先写临时文件再 os.replace,避免半截写入。
        fd, tmp = tempfile.mkstemp(dir=str(self._path.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(cfg.model_dump_json(indent=2))
            os.replace(tmp, self._path)
            # 含明文密钥(同 .env / gateway 取舍):收紧为仅属主可读写(Windows 上无副作用)。
            try:
                os.chmod(self._path, 0o600)
            except OSError:
                pass
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
