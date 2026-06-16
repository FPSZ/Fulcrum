"""前端静态托管:.js 资源必须以 application/javascript 服务(修 Windows text/plain 白屏)。"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from fulcrum.adapters.api.app import _mount_frontend


def _app_with_frontend(root: Path) -> FastAPI:
    (root / "index.html").write_text("<!doctype html><html></html>", encoding="utf-8")
    assets = root / "assets"
    assets.mkdir()
    (assets / "app.js").write_text("export const x = 1\n", encoding="utf-8")
    (assets / "app.css").write_text(".a{color:red}\n", encoding="utf-8")
    app = FastAPI()
    _mount_frontend(app, str(root))
    return app


def test_js_asset_served_as_javascript(tmp_path: Path) -> None:
    client = TestClient(_app_with_frontend(tmp_path))
    r = client.get("/assets/app.js")
    assert r.status_code == 200
    # 关键:不能是 text/plain,否则浏览器按严格 MIME 拒绝执行 ES module。
    assert r.headers["content-type"].split(";")[0] == "application/javascript"


def test_css_asset_served_as_css(tmp_path: Path) -> None:
    client = TestClient(_app_with_frontend(tmp_path))
    r = client.get("/assets/app.css")
    assert r.status_code == 200
    assert r.headers["content-type"].split(";")[0] == "text/css"


def test_spa_fallback_returns_index(tmp_path: Path) -> None:
    client = TestClient(_app_with_frontend(tmp_path))
    r = client.get("/some/client/route")
    assert r.status_code == 200
    assert "<!doctype html>" in r.text.lower()
