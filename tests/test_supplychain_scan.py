"""ManifestScanner:供应链静态扫描评级 + CLI 逻辑。"""

from __future__ import annotations

from fulcrum.capabilities.supplychain.manifest_scanner import ManifestScanner
from fulcrum.core.domain import Context, Disposition
from fulcrum.scan import format_report, load_manifest, scan_manifest

_CTX = Context(session_id="t")


def _scan(manifest: dict):
    return ManifestScanner().scan(manifest, _CTX)


def _kinds(report) -> set[str]:
    return {f.kind for f in report.risks}


def test_benign_manifest_allows() -> None:
    report = _scan(
        {
            "name": "weather",
            "version": "1.0.0",
            "description": "查询天气,只读公开数据",
            "permissions": ["file.read", "network"],
            "endpoints": ["https://api.weather.gov.cn/v1"],
            "dependencies": ["requests==2.31.0"],
        }
    )
    assert report.rating == Disposition.ALLOW
    assert report.component_id == "weather@1.0.0"


def test_command_exec_permission_blocks() -> None:
    report = _scan({"name": "x", "permissions": ["shell.exec"]})
    assert "perm.command_exec" in _kinds(report)
    assert report.rating == Disposition.BLOCK


def test_credential_permission_blocks() -> None:
    report = _scan({"name": "x", "permissions": ["read_credentials"]})
    assert "perm.credential_access" in _kinds(report)
    assert report.rating == Disposition.BLOCK


def test_file_write_permission_requires_approval() -> None:
    report = _scan({"name": "x", "permissions": ["file.write"]})
    assert "perm.file_write" in _kinds(report)
    assert report.rating == Disposition.APPROVE


def test_suspicious_description_blocks() -> None:
    report = _scan({"name": "x", "description": "含反弹 shell 后门,隐蔽外联窃取凭据"})
    susp = [f for f in report.risks if f.kind == "desc.suspicious"]
    assert susp and susp[0].evidence["matched"]
    assert report.rating == Disposition.BLOCK


def test_raw_ip_endpoint_flagged_high() -> None:
    report = _scan({"name": "x", "endpoints": ["http://203.0.113.66:8080/c"]})
    assert "endpoint.raw_ip" in _kinds(report)
    assert report.rating == Disposition.APPROVE  # high → approve


def test_suspicious_host_and_plaintext_http_are_medium() -> None:
    report = _scan(
        {"name": "x", "endpoints": ["https://exfil.duckdns.org/u", "http://plain.example.org/x"]}
    )
    assert "endpoint.suspicious_host" in _kinds(report)
    assert "endpoint.plaintext_http" in _kinds(report)
    assert report.rating == Disposition.SANITIZE  # medium → sanitize


def test_dependency_from_url_flagged_high() -> None:
    report = _scan({"name": "x", "dependencies": ["git+http://198.51.100.7/p.git"]})
    assert "dep.install_from_url" in _kinds(report)
    assert report.rating == Disposition.APPROVE


def test_permission_dedup_one_finding_per_category() -> None:
    report = _scan({"name": "x", "permissions": ["shell.exec", "run_cmd", "subprocess"]})
    assert sum(1 for f in report.risks if f.kind == "perm.command_exec") == 1


def test_empty_manifest_allows() -> None:
    report = _scan({})
    assert report.rating == Disposition.ALLOW
    assert report.component_id == "unknown"


# ---- CLI 逻辑 + 真实样例 ----
def test_cli_scans_benign_sample_allow() -> None:
    manifest = load_manifest("samples/supplychain/benign-weather-skill.yml")
    report = scan_manifest(manifest)
    assert report.rating == Disposition.ALLOW


def test_cli_scans_malicious_sample_block() -> None:
    manifest = load_manifest("samples/supplychain/malicious-exfil-plugin.yml")
    report = scan_manifest(manifest)
    assert report.rating == Disposition.BLOCK
    kinds = {f.kind for f in report.risks}
    assert {"perm.command_exec", "perm.credential_access", "desc.suspicious"} <= kinds
    assert "组件:super-helper-plugin@0.0.7" in format_report(report)
