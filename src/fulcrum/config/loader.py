"""能力装配清单加载(fulcrum.yml)。"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ..core.errors import ConfigError

_DEFAULT_CONFIG = Path(__file__).with_name("fulcrum.yml")

_REQUIRED_KEYS = (
    "labeler",
    "detectors",
    "attributor",
    "risk_scorer",
    "chain_analyzer",
    "policy",
    "executor",
    "tools",
    "scanner",
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
