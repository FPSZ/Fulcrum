"""`python -m fulcrum.openapi` —— 导出 OpenAPI 契约,供前端按其生成 API client。

FastAPI 已据路由 + pydantic schema 自动产出 OpenAPI;本工具把完整 app 的 spec 落盘为
`docs/api/openapi.json`(单一契约真源,前端 codegen 据此对齐后端,避免手抄漂移)。

为避免污染 data/runtime,构建 app 时把鉴权/网关/审计库都指向**临时目录**(用完即弃),
仅为拿到 spec,不留任何运行态副本。
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

_DEFAULT_OUT = "docs/api/openapi.json"


def build_spec() -> dict[str, Any]:
    """构建完整 app(含鉴权/管理/网关路由)并返回其 OpenAPI spec。无持久副作用。"""
    from .app import create_app
    from .config import Settings

    with tempfile.TemporaryDirectory(prefix="fulcrum-openapi-") as tmp:
        settings = Settings(
            log_level="ERROR",  # 抑制构建期日志(含一次性引导口令),保持导出输出干净
            auth_db_path=str(Path(tmp) / "auth.sqlite"),
            gateway_config_path=str(Path(tmp) / "gateway.json"),
            audit_db_path=str(Path(tmp) / "audit.sqlite"),
            bootstrap_admin_password="export-throwaway",  # 临时库随目录销毁
            frontend_dir="",  # 只要 API 契约,不挂前端静态
        )
        app = create_app(settings)
        return app.openapi()


def export(out_path: str | Path = _DEFAULT_OUT) -> dict[str, Any]:
    """生成 spec 并写入 out_path(创建父目录),返回 spec。"""
    spec = build_spec()
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(spec, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return spec


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fulcrum.openapi", description="导出 OpenAPI 契约")
    parser.add_argument("--out", default=_DEFAULT_OUT, help="输出路径(默认 docs/api/openapi.json)")
    args = parser.parse_args(argv)

    spec = export(args.out)
    paths = spec.get("paths", {})
    print(
        f"OpenAPI {spec.get('openapi')} · {spec.get('info', {}).get('title')} "
        f"· {len(paths)} 个路径 → {args.out}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
