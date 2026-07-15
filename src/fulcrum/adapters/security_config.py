"""分级安全预设的持久化与展开。

本模块只保存安全检测配置，不保存模型主对话或网关接入配置。judge 密钥可以落盘，但
公开 DTO 仅回传掩码；真正的运行时替换由 API 路由先构建候选管线后完成。
"""

from __future__ import annotations

import copy
import ipaddress
import os
import tempfile
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator, model_validator

from ..config import DETECTOR_ZONES, normalize_detector_zones
from .net_guard import validate_endpoint

SecurityProfile = Literal["lightweight", "standard", "strict", "air_gapped"]

_RULE_DETECTORS = (
    "keyword_rules",
    "secret_egress",
    "manifest_guard",
    "disclosure_egress",
    "exfil_channel",
)
_CASCADE_DETECTORS = (
    "injection_cascade",
    "secret_egress",
    "manifest_guard",
    "disclosure_egress",
    "exfil_channel",
)
_FULL_JUDGE_DETECTORS = (
    "keyword_rules",
    "llm_judge",
    "secret_egress",
    "manifest_guard",
    "disclosure_egress",
    "exfil_channel",
)


def _same_for_all(detectors: tuple[str, ...]) -> dict[str, list[str]]:
    return {zone: list(detectors) for zone in DETECTOR_ZONES}


def profile_detector_zones(profile: SecurityProfile) -> dict[str, list[str]]:
    """返回预设完整展开后的四区检测器集合。"""
    if profile == "lightweight":
        return _same_for_all(_RULE_DETECTORS)
    if profile == "strict":
        return _same_for_all(_FULL_JUDGE_DETECTORS)
    # 标准与合规档都用级联，差异仅在合规档的 judge 端点只能是本机回环地址。
    return _same_for_all(_CASCADE_DETECTORS)


def available_detector_names(base_config: dict[str, Any]) -> list[str]:
    """返回控制台可选检测器的稳定去重清单，不暴露实现 options。"""
    names: list[str] = []
    seen: set[str] = set()

    def add(detector: str) -> None:
        if detector not in seen:
            seen.add(detector)
            names.append(detector)

    baseline_zones = normalize_detector_zones(base_config["detectors"])
    for zone in DETECTOR_ZONES:
        for detector in baseline_zones[zone]:
            add(detector)
    for profile in ("lightweight", "standard", "strict", "air_gapped"):
        for zone in DETECTOR_ZONES:
            for detector in profile_detector_zones(profile)[zone]:
                add(detector)
    return names


def _is_loopback_endpoint(endpoint: str) -> bool:
    parsed = urlparse(endpoint)
    host = (parsed.hostname or "").lower().rstrip(".")
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class JudgeConfig(BaseModel):
    """语义 judge 的连接信息；仅本模块内部持有 api_key 明文。"""

    endpoint: str = Field(default="http://127.0.0.1:8123/v1", max_length=512)
    model: str = Field(default="qwen3-8b", min_length=1, max_length=128)
    api_key: str = Field(default="", max_length=2048)
    timeout_seconds: float = Field(default=20.0, ge=1, le=120)

    @field_validator("endpoint")
    @classmethod
    def _validate_endpoint(cls, value: str) -> str:
        return validate_endpoint(value.strip())


class SecurityConfig(BaseModel):
    """落盘安全配置：预设先展开，随后由 zone_overrides 覆盖指定区域。"""

    profile: SecurityProfile = "standard"
    zone_overrides: dict[str, list[str]] = Field(default_factory=dict)
    judge: JudgeConfig = Field(default_factory=JudgeConfig)

    @model_validator(mode="after")
    def _validate_profile(self) -> SecurityConfig:
        unknown = sorted(set(self.zone_overrides) - set(DETECTOR_ZONES))
        if unknown:
            raise ValueError(f"未知检测区域:{unknown}")
        for zone, names in self.zone_overrides.items():
            if any(not isinstance(name, str) or not name.strip() for name in names):
                raise ValueError(f"区域 {zone} 的检测器名称不能为空")
        if self.profile != "lightweight" and not self.judge.endpoint.strip():
            raise ValueError("启用 judge 的预设必须配置 judge endpoint")
        if self.profile == "air_gapped" and not _is_loopback_endpoint(self.judge.endpoint):
            raise ValueError("air_gapped 预设的 judge endpoint 仅允许 localhost 或 loopback 地址")
        return self

    def detector_zones(self) -> dict[str, list[str]]:
        zones = profile_detector_zones(self.profile)
        for zone, names in self.zone_overrides.items():
            zones[zone] = list(names)
        return zones

    def apply_to(self, base_config: dict[str, Any]) -> dict[str, Any]:
        """生成可交给 build_pipeline 的完整候选配置，不改动静态基线。"""
        cfg = copy.deepcopy(base_config)
        cfg["detectors"] = self.detector_zones()
        cfg.pop("detector_zones", None)
        options = cfg.setdefault("options", {})
        judge = {
            "endpoint": self.judge.endpoint,
            "model": self.judge.model,
            "api_key": self.judge.api_key,
            "timeout": self.judge.timeout_seconds,
        }
        if self.profile != "lightweight":
            options["llm_judge"] = dict(judge)
            options["injection_cascade"] = {
                "gray_low": 0.0,
                "gray_high": 0.6,
                "judge": dict(judge),
            }
        return cfg


def _mask(secret: str) -> str:
    if not secret:
        return ""
    return ("*" * 6 + secret[-4:]) if len(secret) > 4 else "*" * len(secret)


class SecurityConfigPublic(BaseModel):
    profile: SecurityProfile
    detector_zones: dict[str, list[str]]
    judge_endpoint: str
    judge_model: str
    judge_api_key_masked: str
    judge_api_key_set: bool
    judge_timeout_seconds: float

    @classmethod
    def of(cls, cfg: SecurityConfig) -> SecurityConfigPublic:
        return cls(
            profile=cfg.profile,
            detector_zones=cfg.detector_zones(),
            judge_endpoint=cfg.judge.endpoint,
            judge_model=cfg.judge.model,
            judge_api_key_masked=_mask(cfg.judge.api_key),
            judge_api_key_set=bool(cfg.judge.api_key),
            judge_timeout_seconds=cfg.judge.timeout_seconds,
        )


class SecurityConfigStore:
    """安全预设 JSON 存储；低频写使用临时文件 + replace 保证原子性。"""

    def __init__(self, path: str, seed: SecurityConfig | None = None) -> None:
        self._path = Path(path)
        self._seed = seed or SecurityConfig()
        self._cache: SecurityConfig | None = None

    def load(self) -> SecurityConfig:
        if self._cache is not None:
            return self._cache
        if self._path.is_file():
            try:
                self._cache = SecurityConfig.model_validate_json(
                    self._path.read_text(encoding="utf-8")
                )
            except (OSError, ValueError):
                self._cache = self._seed
        else:
            self._cache = self._seed
            self._write(self._cache)
        return self._cache

    def save(self, cfg: SecurityConfig) -> SecurityConfig:
        self._write(cfg)
        self._cache = cfg
        return cfg

    def _write(self, cfg: SecurityConfig) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self._path.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(cfg.model_dump_json(indent=2))
            os.replace(tmp, self._path)
            try:
                os.chmod(self._path, 0o600)
            except OSError:
                pass
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
