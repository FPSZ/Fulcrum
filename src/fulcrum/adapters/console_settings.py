"""控制台通用设置 —— 运行时可改、落盘持久化(Docker 卷),设置页填表即存。

覆盖设置页"通用 / 审计留存 / 通知"三组**实例级偏好**(非安全红线项)。安全相关配置
另有归属:上游接入见 ``gateway`` 模块,模型出站见 .env,事件对话展示见前端 localStorage。

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
Language = Literal["zh", "en"]
Timezone = Literal["sh", "utc"]
ChainVerify = Literal["event", "5m", "1h"]
Retention = Literal["90d", "180d", "1y", "forever"]
ExportFormat = Literal["jsonl", "csv"]
NotifyChannel = Literal["inapp", "webhook", "email"]


class ConsoleSettings(BaseModel):
    """控制台实例级偏好(单实例)。字段即设置页表单项。"""

    # 通用
    instance_name: str = Field(default="枢衡安全控制台", max_length=64)
    environment: Environment = "demo"
    language: Language = "zh"
    timezone: Timezone = "sh"
    # 审计与留存
    chain_verify_freq: ChainVerify = "event"
    audit_retention: Retention = "1y"
    export_format: ExportFormat = "jsonl"
    # 通知
    notify_severe: bool = True
    notify_approval: bool = True
    notify_channel: NotifyChannel = "inapp"


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
