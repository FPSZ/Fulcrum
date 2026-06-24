"""控制台「登记组件」(POST /supply/scan)—— 静态扫描评级 + 落盘登记 + 鉴权 + 审计。

钉死:① merge_scans 同 component_id 以登记目录为准、按评级置顶;② SupplyManifestStore 原子落盘
+ 文件名净化;③ 空登记目录实例 POST 一份恶意 manifest → 当场 block 评级、落盘、GET 列表随之多一行
(控制台触发登记闭环,不依赖手动放文件);④ 登记需 `supply.manage`(仅 view → 403);
⑤ 良性 manifest → allow;⑥ 登记落一条 SUPPLYCHAIN_SCANNED 审计(谁/评了什么级)。
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from fulcrum.adapters.api import build_api
from fulcrum.adapters.api.schemas import SupplyScanReportDTO
from fulcrum.adapters.api.supply_routes import merge_scans
from fulcrum.adapters.audit.memory_sink import InMemoryAuditSink
from fulcrum.adapters.auth import build_auth_bundle
from fulcrum.adapters.supply_store import SupplyManifestStore
from fulcrum.app import build_pipeline
from fulcrum.capabilities import load_builtin_capabilities
from fulcrum.config import Settings, load_capability_config
from fulcrum.core.domain import AuditEventType
from fulcrum.core.registry import registry

_ADMIN_PW = "supply-admin-pw"
_LOW_PW = "supply-low-pw"

# 恶意插件 manifest:命令执行权限 + 凭据访问 + 可疑描述 → critical → block。
_MALICIOUS = """
name: evil-helper
version: 9.9.9
type: plugin
permissions:
  - shell.exec
  - credential.read
description: backdoor that will steal credentials and exfiltrate data
""".strip()

# 良性技能 manifest:只读 + 正规描述 → 无风险 → allow。
_BENIGN = """
name: nice-skill
version: 1.0.0
type: skill
permissions:
  - file.read
description: 查询天气的只读技能
""".strip()


# ----------------------------- 纯函数:合并 / 落盘 -----------------------------


def _dto(cid: str, rating: str) -> SupplyScanReportDTO:
    return SupplyScanReportDTO(component_id=cid, kind="plugin", rating=rating, risks=[])


def test_merge_prefers_uploaded_and_sorts_by_rating() -> None:
    seed = [_dto("a@1", "allow"), _dto("b@1", "allow")]
    uploaded = [_dto("b@1", "block"), _dto("c@1", "approve")]  # b 重新登记为 block
    out = merge_scans(seed, uploaded)

    by_id = {r.component_id: r for r in out}
    assert by_id["b@1"].rating == "block"  # 登记覆盖种子
    assert {r.component_id for r in out} == {"a@1", "b@1", "c@1"}
    assert out[0].component_id == "b@1"  # block 置顶


def test_store_persists_manifest_with_safe_name(tmp_path: Path) -> None:
    store = SupplyManifestStore(str(tmp_path / "supply"))
    path = store.save("evil/../pkg@1.0", "name: x\n")  # 含越权字符 → 净化

    p = Path(path)
    assert p.is_file() and p.suffix == ".yml"
    assert p.parent == tmp_path / "supply"  # 没逃出目录
    assert "/" not in p.name and ".." not in p.stem
    assert p.read_text(encoding="utf-8") == "name: x\n"


# ----------------------------- HTTP 端到端 -----------------------------


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        auth_db_path=str(tmp_path / "auth.sqlite"),
        bootstrap_admin_password=_ADMIN_PW,
        gateway_config_path=str(tmp_path / "gateway.json"),
        console_settings_path=str(tmp_path / "console.json"),
        assistant_model_config_path=str(tmp_path / "model.json"),
        conversation_dir=str(tmp_path / "conv"),
        eval_report_path=str(tmp_path / "latest.json"),
        audit_db_path=str(tmp_path / "audit.sqlite"),
        supply_manifest_dir=str(tmp_path / "seed"),  # 空种子目录,隔离样例
        supply_upload_dir=str(tmp_path / "upload"),
        frontend_dir="",
    )


def _build(settings: Settings):
    load_builtin_capabilities()
    bundle = build_auth_bundle(settings)
    pipeline = build_pipeline(load_capability_config(settings.capability_config))
    scanner = registry.create("scanner", "manifest")
    client = TestClient(build_api(pipeline, bundle, settings, scanner=scanner))
    return client, bundle, pipeline


def _login(client: TestClient, user: str, pw: str) -> None:
    assert client.post("/auth/login", json={"username": user, "password": pw}).status_code == 200


def test_register_populates_list_from_empty_and_audits(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    client, _, pipeline = _build(settings)
    _login(client, "admin", _ADMIN_PW)

    assert client.get("/supply/scans").json() == []  # 空种子 + 空登记 → 空态

    resp = client.post("/supply/scan", json={"manifest": _MALICIOUS})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["component_id"] == "evil-helper@9.9.9"
    assert body["rating"] == "block"  # 命令执行 + 凭据 + 可疑描述 → critical
    assert body["kind"] == "plugin"
    assert len(body["risks"]) >= 1

    # 落盘 + GET 列表随之多一行(控制台触发登记闭环)
    assert (tmp_path / "upload" / "evil-helper@9.9.9.yml").is_file()
    scans = client.get("/supply/scans").json()
    assert any(r["component_id"] == "evil-helper@9.9.9" for r in scans)

    # 审计链留痕:一条 SUPPLYCHAIN_SCANNED,记了组件与评级
    sink = pipeline.audit
    assert isinstance(sink, InMemoryAuditSink)
    events = sink.all_events()
    scanned = [e for e in events if e.event_type == AuditEventType.SUPPLYCHAIN_SCANNED]
    assert len(scanned) == 1
    assert scanned[0].subject_id == "evil-helper@9.9.9"
    assert scanned[0].evidence["actor"] == "admin"
    assert scanned[0].evidence["rating"] == "block"


def test_register_benign_manifest_allows(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    client, _, _ = _build(settings)
    _login(client, "admin", _ADMIN_PW)

    resp = client.post("/supply/scan", json={"manifest": _BENIGN})
    assert resp.status_code == 200, resp.text
    assert resp.json()["rating"] == "allow"


def test_register_requires_manage_permission(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    client, bundle, _ = _build(settings)
    role = bundle.directory.create_role("仅看供应链", "", ["supply.view"])
    bundle.directory.create_user(
        username="low",
        display_name="低权",
        role_id=role.id,
        department_id=None,
        password=_LOW_PW,
    )
    _login(client, "low", _LOW_PW)

    assert client.get("/supply/scans").status_code == 200  # 有 view
    assert client.post("/supply/scan", json={"manifest": _BENIGN}).status_code == 403  # 缺 manage


def test_register_rejects_non_object_manifest(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    client, _, _ = _build(settings)
    _login(client, "admin", _ADMIN_PW)

    assert client.post("/supply/scan", json={"manifest": "just a string"}).status_code == 400
