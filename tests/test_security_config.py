"""分级安全预设：展开、私有化边界、持久化与运行中管线热替换。"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError

from fulcrum.adapters.api.security_config_routes import register_security_config_routes
from fulcrum.adapters.auth.models import Principal
from fulcrum.adapters.security_config import (
    SecurityConfig,
    SecurityConfigStore,
    available_detector_names,
)
from fulcrum.app import build_pipeline
from fulcrum.config import DETECTOR_ZONES
from fulcrum.core.domain import AuditEventType
from fulcrum.core.errors import ConfigError
from fulcrum.core.pipeline import SecurityPipeline

_BASE_CONFIG = {
    "labeler": "passthrough",
    "detectors": ["keyword_rules"],
    "attributor": "evidence",
    "risk_scorer": "heuristic",
    "chain_analyzer": "noop",
    "policy": "allow_all",
    "executor": "echo",
    "tools": ["echo"],
    "model": "fake",
    "audit": "memory",
}


class _Deps:
    def __init__(self, permissions: frozenset[str]) -> None:
        self._principal = Principal(
            user_id=1,
            username="admin",
            display_name="管理员",
            role_key="admin",
            role_name="管理员",
            permissions=permissions,
        )

    def require(self, permission: str):  # type: ignore[no-untyped-def]
        def _guard() -> Principal:
            if permission not in self._principal.permissions:
                raise HTTPException(status_code=403, detail=f"无权限:需要 {permission}")
            return self._principal

        return _guard


def _client(
    tmp_path: Path, permissions: frozenset[str]
) -> tuple[TestClient, SecurityPipeline, SecurityConfigStore]:
    store = SecurityConfigStore(str(tmp_path / "security.json"))
    pipeline = build_pipeline(store.load().apply_to(_BASE_CONFIG))
    app = FastAPI()
    register_security_config_routes(
        app,
        pipeline,
        store,
        _BASE_CONFIG,
        build_pipeline,
        _Deps(permissions),  # type: ignore[arg-type]
    )
    return TestClient(app), pipeline, store


@pytest.mark.parametrize("profile", ["lightweight", "standard", "strict", "air_gapped"])
def test_profile_expands_to_all_detector_zones(profile: str) -> None:
    config = SecurityConfig(profile=profile)  # type: ignore[arg-type]

    zones = config.detector_zones()
    assert tuple(zones) == DETECTOR_ZONES
    assert all(isinstance(names, list) for names in zones.values())


def test_default_profile_preserves_existing_rule_baseline() -> None:
    config = SecurityConfig()

    assert config.profile == "lightweight"
    assert all("injection_cascade" not in names for names in config.detector_zones().values())


def test_zone_override_replaces_only_that_zone() -> None:
    config = SecurityConfig(
        profile="standard", zone_overrides={"gateway_output": ["secret_egress"]}
    )

    zones = config.detector_zones()
    assert zones["gateway_output"] == ["secret_egress"]
    assert "injection_cascade" in zones["gateway_input"]


def test_available_detectors_merges_static_baseline_and_all_profiles() -> None:
    names = available_detector_names(_BASE_CONFIG)

    assert names[0] == "keyword_rules"
    assert "injection_cascade" in names
    assert "llm_judge" in names
    assert len(names) == len(set(names))


@pytest.mark.parametrize("endpoint", ["", "https://8.8.8.8/v1", "http://10.0.0.2/v1"])
def test_air_gapped_rejects_missing_or_non_loopback_judge(endpoint: str) -> None:
    with pytest.raises(ValidationError):
        SecurityConfig(profile="air_gapped", judge={"endpoint": endpoint, "model": "local"})


def test_store_persists_and_public_view_masks_judge_key(tmp_path: Path) -> None:
    path = str(tmp_path / "security.json")
    store = SecurityConfigStore(path)
    store.save(SecurityConfig(judge={"api_key": "supersecret123"}))

    assert SecurityConfigStore(path).load().judge.api_key == "supersecret123"


def test_corrupt_security_config_refuses_to_lower_the_profile(tmp_path: Path) -> None:
    path = tmp_path / "security.json"
    path.write_text("{not-json", encoding="utf-8")

    with pytest.raises(ConfigError, match="安全配置文件无法读取或校验"):
        SecurityConfigStore(str(path)).load()


def test_security_config_route_applies_candidate_and_never_returns_key(tmp_path: Path) -> None:
    client, pipeline, store = _client(tmp_path, frozenset({"settings.view", "settings.manage"}))

    created = client.put(
        "/admin/security-config",
        json={
            "profile": "lightweight",
            "zone_overrides": {"gateway_input": ["noop"]},
            "judge_endpoint": "http://127.0.0.1:8123/v1",
            "judge_model": "qwen3-8b",
            "judge_api_key": "supersecret123",
        },
    )
    assert created.status_code == 200, created.text
    assert "supersecret" not in created.text
    assert created.json()["judge_api_key_set"] is True
    assert {"keyword_rules", "injection_cascade", "llm_judge"} <= set(
        created.json()["available_detectors"]
    )
    assert [d.name for d in pipeline.detector_zones["gateway_input"]] == ["noop"]
    assert store.load().profile == "lightweight"
    events = asyncio.run(pipeline.audit.events("security-config:1"))
    event = next(
        event for event in events if event.event_type == AuditEventType.SECURITY_CONFIG_UPDATED
    )
    assert event.evidence["actor"] == "admin"
    assert event.evidence["profile"] == "lightweight"
    assert "gateway_input" in event.evidence["changed_zones"]
    assert "supersecret123" not in str(event.evidence)
    assert "127.0.0.1" not in str(event.evidence)

    preserved = client.put(
        "/admin/security-config",
        json={
            "profile": "lightweight",
            "zone_overrides": {"gateway_input": ["noop"]},
            "judge_endpoint": "http://127.0.0.1:8123/v1",
            "judge_model": "qwen3-8b",
            "judge_api_key": None,
        },
    )
    assert preserved.status_code == 200
    assert store.load().judge.api_key == "supersecret123"

    cleared = client.put(
        "/admin/security-config",
        json={
            "profile": "lightweight",
            "zone_overrides": {"gateway_input": ["noop"]},
            "judge_endpoint": "http://127.0.0.1:8123/v1",
            "judge_model": "qwen3-8b",
            "judge_api_key": "",
        },
    )
    assert cleared.status_code == 200
    assert store.load().judge.api_key == ""


def test_invalid_candidate_keeps_file_and_running_pipeline(tmp_path: Path) -> None:
    client, pipeline, store = _client(tmp_path, frozenset({"settings.view", "settings.manage"}))
    before = store.load().model_dump_json()
    names_before = [d.name for d in pipeline.detector_zones["gateway_input"]]

    response = client.put(
        "/admin/security-config",
        json={
            "profile": "lightweight",
            "zone_overrides": {"gateway_input": ["does_not_exist"]},
            "judge_endpoint": "http://127.0.0.1:8123/v1",
            "judge_model": "qwen3-8b",
        },
    )

    assert response.status_code == 400
    assert store.load().model_dump_json() == before
    assert [d.name for d in pipeline.detector_zones["gateway_input"]] == names_before


def test_security_config_route_requires_settings_permissions(tmp_path: Path) -> None:
    client, _, _ = _client(tmp_path, frozenset())

    assert client.get("/admin/security-config").status_code == 403
    assert (
        client.put(
            "/admin/security-config",
            json={
                "profile": "lightweight",
                "judge_endpoint": "http://127.0.0.1:8123/v1",
                "judge_model": "qwen3-8b",
            },
        ).status_code
        == 403
    )
