"""能力装配清单加载(fulcrum.yml)。"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ..core.errors import ConfigError

_DEFAULT_CONFIG = Path(__file__).with_name("fulcrum.yml")

# 请求级安全管线的装配字段。供应链扫描(scanner port)是**组件登记/上线时**的离线关切,
# 不在每请求管线里(否则等于每次工具调用都重扫供应链),故不列入此处;其端口/实现保留,
# 待供应链能力真实化时由独立流程单独装配。
_REQUIRED_KEYS = (
    "labeler",
    "detectors",
    "attributor",
    "risk_scorer",
    "chain_analyzer",
    "policy",
    "executor",
    "tools",
    "model",
    "audit",
)


def load_capability_config(path: str | None = None) -> dict[str, Any]:
    cfg_path = Path(path) if path else _DEFAULT_CONFIG
    if not cfg_path.exists():
        raise ConfigError(f"装配清单不存在:{cfg_path}")
    with cfg_path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    missing = [k for k in _REQUIRED_KEYS if k not in data]
    if missing:
        raise ConfigError(f"装配清单缺少字段:{missing}(文件:{cfg_path})")
    return data
