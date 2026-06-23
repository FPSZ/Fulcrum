"""控制台实例设置 —— 运行时可改、落盘持久化(Docker 卷),设置页填表即存。

只覆盖真正有后端落点的实例元信息。安全相关配置另有归属:上游接入见 ``gateway`` 模块,
模型出站见 .env,事件对话展示见前端 localStorage。不要把尚未生效的安全策略、通知渠道、
审计留存任务伪装成可配置项。

低频写,JSON 文件足够;原子替换避免半截写入。Docker 部署挂卷于 data/runtime 即持久化。
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

Environment = Literal["prod", "staging", "demo"]


class ConsoleSettings(BaseModel):
    """控制台实例级元信息(单实例)。字段即设置页真实可写项。"""

    instance_name: str = Field(default="枢衡安全控制台", max_length=64)
    environment: Environment = "demo"


class ConsoleSettingsStore:
    """JSON 文件持久化(放 data/runtime,挂 Docker 卷即不丢)。低频写,文件足够。"""

    def __init__(self, path: str, seed: ConsoleSettings | None = None) -> None:
        self._path = Path(path)
        self._seed = seed or ConsoleSettings()
        self._cache: ConsoleSettings | None = None

    def load(self) -> ConsoleSettings:
        if self._cache is not None:
            return self._cache
        if self._path.is_file():
            try:
                data = json.loads(self._path.read_text(encoding="utf-8"))
                self._cache = ConsoleSettings.model_validate(data)
            except (json.JSONDecodeError, ValueError, OSError):
                self._cache = self._seed
        else:
            self._cache = self._seed
            self._write(self._cache)  # 首启落种子,设置页即见默认值
        return self._cache

    def save(self, cfg: ConsoleSettings) -> ConsoleSettings:
        self._write(cfg)
        self._cache = cfg
        return cfg

    def _write(self, cfg: ConsoleSettings) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # 原子替换:先写临时文件再 os.replace,避免半截写入。
        fd, tmp = tempfile.mkstemp(dir=str(self._path.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(cfg.model_dump_json(indent=2))
            os.replace(tmp, self._path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
