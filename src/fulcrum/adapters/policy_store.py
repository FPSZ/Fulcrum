"""策略覆盖文档落盘 —— 控制台编辑后的安全策略持久化(Docker 卷),重启不丢。

种子策略仍是版本化的 `data/policies/default.yml`(随仓库走);控制台一旦改过策略,改后的
完整文档落到 `data/runtime/policy.yml`(gitignore + 挂卷)。启动时若存在覆盖文档则以它为准,
否则用种子——与 `GatewayConfigStore`/`ConsoleSettingsStore` 同模式(低频写、原子替换、热加载缓存)。

只做 I/O:文档的合法性校验归策略引擎(`YamlPolicyEngine._validate`),本 store 不碰检测语义,
故不依赖 capabilities(保持 adapters↛capabilities 边界)。
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

import yaml


class PolicyDocStore:
    """策略文档(纯 dict)的 YAML 持久化。放 data/runtime,挂 Docker 卷即不丢。"""

    def __init__(self, path: str) -> None:
        self._path = Path(path)

    def load(self) -> dict[str, Any] | None:
        """返回控制台改后的覆盖文档;从未改过(文件不存在)或损坏 → None(调用方回落种子)。"""
        if not self._path.is_file():
            return None
        try:
            data = yaml.safe_load(self._path.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError):
            return None
        return data if isinstance(data, dict) else None

    def save(self, doc: dict[str, Any]) -> None:
        """原子写覆盖文档(先写临时文件再 os.replace,避免半截写入读到坏策略)。"""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self._path.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                yaml.safe_dump(doc, f, allow_unicode=True, sort_keys=False)
            os.replace(tmp, self._path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
