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
    "/eval/report",
    "/policies",
    "/supply/scans",
    "/tools/calls",
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


def test_committed_spec_matches_current_app() -> None:
    """入库的 docs/api/openapi.json 必须与当前应用契约一致(漂移门禁)。

    缺口来源(docs/status/03 §4.1):此前入库副本停在 version 0.0.0 / 32 路径,而应用已是
    0.5.0 / 45 路径——助手聊天、流式、确认、撤销、审批、模型配置、事件处置、团队成员等
    整批端点在契约里查不到。既有用例只验「生成函数能跑、格式合法」,不比对入库文件,
    所以漂移可以无声积累。本用例把两者钉在一起:改了路由却忘了重新导出即红。

    修法:`uv run python -m fulcrum.openapi` 重新导出后提交。
    """
    committed = json.loads(Path("docs/api/openapi.json").read_text(encoding="utf-8"))
    current = build_spec()
    assert committed["info"]["version"] == current["info"]["version"], (
        "入库契约版本落后于包版本,请重新导出 openapi.json"
    )
    drift_missing = sorted(set(current["paths"]) - set(committed["paths"]))
    drift_stale = sorted(set(committed["paths"]) - set(current["paths"]))
    assert not drift_missing, f"入库契约缺少当前应用已有的路径:{drift_missing}"
    assert not drift_stale, f"入库契约含当前应用已无的路径:{drift_stale}"
