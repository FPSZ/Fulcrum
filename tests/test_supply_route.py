"""供应链扫描只读端点:对组件 manifest 目录跑静态扫描,产出评级报告。

验证供应链页接真的后端契约:扫描器对真实样例 manifest 给出预期评级(恶意 block / 良性 allow),
报告映射为 DTO(风险项按分值降序),目录缺失时诚实返回空。
"""

from __future__ import annotations

from pathlib import Path

from fulcrum.adapters.api.supply_routes import scan_directory, to_scan_report_dto
from fulcrum.capabilities import load_builtin_capabilities
from fulcrum.core.registry import registry


def _scanner():
    load_builtin_capabilities()
    return registry.create("scanner", "manifest")


def test_scan_directory_rates_sample_manifests() -> None:
    reports = scan_directory(_scanner(), "samples/supplychain")
    by_id = {r.component_id: r for r in reports}

    assert "super-helper-plugin@0.0.7" in by_id
    assert "weather-query-skill@1.2.0" in by_id

    mal = by_id["super-helper-plugin@0.0.7"]
    assert mal.rating == "block"  # 命令执行 + 凭据访问 + 可疑描述 → critical
    assert mal.kind == "plugin"  # 据文件名推断
    assert len(mal.risks) >= 4
    # 风险项按分值降序;高危项(critical)排在前
    scores = [r.score for r in mal.risks]
    assert scores == sorted(scores, reverse=True)
    assert mal.risks[0].severity == "critical"
    assert mal.risks[0].detail  # 有说明文案

    benign = by_id["weather-query-skill@1.2.0"]
    assert benign.rating == "allow"  # 只读 + https + 正规依赖
    assert benign.kind == "skill"

    # 列表按评级严重度置顶(block 在前)
    assert reports[0].rating == "block"


def test_missing_dir_returns_empty(tmp_path: Path) -> None:
    assert scan_directory(_scanner(), str(tmp_path / "nope")) == []


def test_to_scan_report_dto_maps_rating_and_risks() -> None:
    scanner = _scanner()
    from fulcrum.core.domain import Context

    manifest = {"name": "x", "version": "1.0", "permissions": ["shell.exec"]}
    report = scanner.scan(manifest, Context(session_id="t"))
    dto = to_scan_report_dto(report, "plugin")
    assert dto.component_id == "x@1.0"
    assert dto.kind == "plugin"
    assert dto.rating == "block"  # shell.exec → command_exec → critical
    assert any(r.kind == "perm.command_exec" for r in dto.risks)
