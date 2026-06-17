"""OpenAPI 契约导出:spec 结构、关键路径覆盖、落盘无持久副作用。"""

from __future__ import annotations

import json
from pathlib import Path

from fulcrum.openapi import build_spec, export

# 必须出现在契约里的关键路径(覆盖核心安全 + 网关 + 鉴权 + 管理)。
_REQUIRED_PATHS = {
    "/healthz",
    "/v1/chat/completions",
    "/tools/call",
    "/audit/{session_id}",
    "/audit",
    "/gateway/chat",
    "/overview/stats",
    "/events",
    "/admin/gateway-config",
    "/auth/login",
    "/admin/users",
}


def test_build_spec_shape_and_paths() -> None:
    spec = build_spec()
    assert spec["openapi"].startswith("3.")
    assert spec["info"]["title"] == "枢衡 Fulcrum API"
    missing = _REQUIRED_PATHS - set(spec["paths"])
    assert not missing, f"契约缺少关键路径:{sorted(missing)}"


def test_export_writes_valid_json(tmp_path: Path) -> None:
    out = tmp_path / "openapi.json"
    export(out)
    assert out.exists()
    spec = json.loads(out.read_text(encoding="utf-8"))
    assert "paths" in spec and "/healthz" in spec["paths"]


def test_export_leaves_no_runtime_side_effects(tmp_path: Path) -> None:
    """导出用临时库,不应在 data/runtime 新建文件。"""
    before = set(Path("data/runtime").glob("*")) if Path("data/runtime").exists() else set()
    export(tmp_path / "o.json")
    after = set(Path("data/runtime").glob("*")) if Path("data/runtime").exists() else set()
    assert before == after
