"""配置子系统:运行时 Settings + 能力装配清单。"""

from __future__ import annotations

from .loader import DETECTOR_ZONES, load_capability_config, normalize_detector_zones
from .settings import Settings

__all__ = ["DETECTOR_ZONES", "Settings", "load_capability_config", "normalize_detector_zones"]
