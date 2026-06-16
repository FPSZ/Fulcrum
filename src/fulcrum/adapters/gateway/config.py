"""网关上游接入配置 —— 运行时可改、落盘持久化(Docker 卷),买家在设置页填表即生效。

设计目标:**面向企业通用接入**,不绑定我们自己的 demo。
一个买家拿到镜像后,只需在设置页填:上游地址、协议、认证、模型名,点"测试连接"通过即保存。
配置热加载(每次请求读当前配置),无需改 .env 或重启容器。

协议:
- ``openai`` —— OpenAI 兼容 /chat/completions(覆盖 OpenClaw 类及市面绝大多数智能体/LLM 网关)
- ``rest``   —— 通用 REST:可配请求字段名 + 响应取值路径,适配任意自研 HTTP 接口
- ``native`` —— 我们自己的 /chat 协议(配套内置企业智能体 demo)

密钥(auth_value)落盘但**绝不原样回前端**:对外一律掩码。
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

Protocol = Literal["openai", "rest", "native"]
AuthType = Literal["none", "bearer", "header"]


class GatewayConfig(BaseModel):
    """上游接入配置(单实例)。字段即设置页表单项。"""

    enabled: bool = True
    name: str = Field(default="默认上游", max_length=64)
    protocol: Protocol = "native"
    endpoint: str = Field(default="http://127.0.0.1:8800", max_length=512)
    path: str = Field(default="", max_length=256)  # 留空按协议取默认
    model: str = Field(default="", max_length=128)  # openai 协议用
    auth_type: AuthType = "none"
    auth_header: str = Field(default="Authorization", max_length=64)
    auth_value: str = Field(default="", max_length=2048)  # 密钥/令牌(明文落盘,不回前端)
    timeout_seconds: float = Field(default=60.0, ge=1, le=600)
    verify_tls: bool = True
    # 通用 REST 映射
    rest_message_field: str = Field(default="message", max_length=64)
    rest_response_path: str = Field(default="reply", max_length=128)  # 点路径,如 data.answer

    def default_path(self) -> str:
        if self.path:
            return self.path
        if self.protocol == "openai":
            return "/chat/completions"
        if self.protocol == "native":
            return "/chat"
        return "/"

    def target_url(self) -> str:
        return f"{self.endpoint.rstrip('/')}{self.default_path()}"

    def auth_headers(self) -> dict[str, str]:
        if self.auth_type == "none" or not self.auth_value:
            return {}
        if self.auth_type == "bearer":
            return {"Authorization": f"Bearer {self.auth_value}"}
        return {self.auth_header or "Authorization": self.auth_value}


def _mask(secret: str) -> str:
    if not secret:
        return ""
    return ("•" * 6 + secret[-4:]) if len(secret) > 4 else "•" * len(secret)


class GatewayConfigPublic(BaseModel):
    """回前端的安全视图:密钥掩码,只暴露"是否已设置"。"""

    enabled: bool
    name: str
    protocol: Protocol
    endpoint: str
    path: str
    model: str
    auth_type: AuthType
    auth_header: str
    auth_value_masked: str
    auth_value_set: bool
    timeout_seconds: float
    verify_tls: bool
    rest_message_field: str
    rest_response_path: str

    @classmethod
    def of(cls, c: GatewayConfig) -> GatewayConfigPublic:
        return cls(
            enabled=c.enabled,
            name=c.name,
            protocol=c.protocol,
            endpoint=c.endpoint,
            path=c.path,
            model=c.model,
            auth_type=c.auth_type,
            auth_header=c.auth_header,
            auth_value_masked=_mask(c.auth_value),
            auth_value_set=bool(c.auth_value),
            timeout_seconds=c.timeout_seconds,
            verify_tls=c.verify_tls,
            rest_message_field=c.rest_message_field,
            rest_response_path=c.rest_response_path,
        )


class GatewayConfigStore:
    """JSON 文件持久化(放 data/runtime,挂 Docker 卷即不丢)。低频写,文件足够。"""

    def __init__(self, path: str, seed: GatewayConfig | None = None) -> None:
        self._path = Path(path)
        self._seed = seed or GatewayConfig()
        self._cache: GatewayConfig | None = None

    def load(self) -> GatewayConfig:
        if self._cache is not None:
            return self._cache
        if self._path.is_file():
            try:
                data = json.loads(self._path.read_text(encoding="utf-8"))
                self._cache = GatewayConfig.model_validate(data)
            except (json.JSONDecodeError, ValueError, OSError):
                self._cache = self._seed
        else:
            self._cache = self._seed
            self._write(self._cache)  # 首启落种子,方便买家看到默认表单
        return self._cache

    def save(self, cfg: GatewayConfig) -> GatewayConfig:
        self._write(cfg)
        self._cache = cfg
        return cfg

    def _write(self, cfg: GatewayConfig) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # 原子替换:先写临时文件再 os.replace,避免半截写入。
        fd, tmp = tempfile.mkstemp(dir=str(self._path.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(cfg.model_dump_json(indent=2))
            os.replace(tmp, self._path)
            # 含明文密钥(同 .env 取舍):尽量收紧为仅属主可读写(Windows 上无副作用)。
            try:
                os.chmod(self._path, 0o600)
            except OSError:
                pass
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
