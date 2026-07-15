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

# 四道安全闸门是分区检测配置的固定契约。新增区域需要同步评审管线入口、审计口径和
# 控制台展示，不能让 YAML 任意扩张后静默失效。
DETECTOR_ZONES: tuple[str, ...] = (
    "gateway_input",
    "gateway_output",
    "tool_return",
    "assistant_intent",
)


def normalize_detector_zones(detectors: Any) -> dict[str, list[str]]:
    """把旧扁平 detectors 或四区映射规范化为按区域的检测器名称。

    扁平列表是历史配置，语义保持为四个区域使用完全相同的检测器集。新的映射格式
    必须显式覆盖全部固定区域，避免漏配区域在运行期退化为无检测。
    """
    if isinstance(detectors, list):
        names = _validate_detector_names(detectors, "detectors")
        return {zone: list(names) for zone in DETECTOR_ZONES}

    if not isinstance(detectors, dict):
        raise ConfigError("detectors 必须是检测器名称列表或按区域分组的映射")

    configured = set(detectors)
    expected = set(DETECTOR_ZONES)
    unknown = sorted(configured - expected)
    missing = sorted(expected - configured)
    if unknown or missing:
        details: list[str] = []
        if unknown:
            details.append(f"未知区域:{unknown}")
        if missing:
            details.append(f"缺少区域:{missing}")
        raise ConfigError(f"detectors 分区配置无效({'; '.join(details)})")

    return {
        zone: _validate_detector_names(detectors[zone], f"detectors.{zone}")
        for zone in DETECTOR_ZONES
    }


def _validate_detector_names(value: Any, field: str) -> list[str]:
    if not isinstance(value, list):
        raise ConfigError(f"{field} 必须是检测器名称列表")
    if any(not isinstance(name, str) or not name.strip() for name in value):
        raise ConfigError(f"{field} 只能包含非空检测器名称")
    return list(value)


def load_capability_config(path: str | None = None) -> dict[str, Any]:
    cfg_path = Path(path) if path else _DEFAULT_CONFIG
    if not cfg_path.exists():
        raise ConfigError(f"装配清单不存在:{cfg_path}")
    with cfg_path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    missing = [k for k in _REQUIRED_KEYS if k not in data]
    if missing:
        raise ConfigError(f"装配清单缺少字段:{missing}(文件:{cfg_path})")
    # 保留原 detectors 字段，供旧调用方读取；规范化结果是新区域化契约的单一入口。
    data["detector_zones"] = normalize_detector_zones(data["detectors"])
    return data
