"""配置子系统:运行时 Settings + 能力装配清单。"""

from __future__ import annotations

from .loader import load_capability_config
from .settings import Settings

__all__ = ["Settings", "load_capability_config"]
