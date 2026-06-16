"""`python -m fulcrum.scan <manifest>` —— 对插件/Skill/MCP 的 manifest 做供应链静态扫描评级。

退出码:0=allow,1=sanitize/approve(需复核),2=block。便于脚本/CI 据评级门禁。
"""

from __future__ import annotations

import argparse
import sys

from . import EXIT_CODE, format_report, load_manifest, scan_manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="fulcrum.scan", description="供应链 manifest 静态扫描评级"
    )
    parser.add_argument("manifest", help="manifest 文件路径(YAML/JSON)")
    parser.add_argument("--scanner", default=None, help="指定扫描器实现名(默认 manifest)")
    args = parser.parse_args(argv)

    try:
        manifest = load_manifest(args.manifest)
    except (FileNotFoundError, ValueError) as exc:
        print(f"错误:{exc}", file=sys.stderr)
        return 3

    report = scan_manifest(manifest, args.scanner)
    print(format_report(report))
    return EXIT_CODE.get(report.rating, 0)


if __name__ == "__main__":
    sys.exit(main())
