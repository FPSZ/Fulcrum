"""`python -m fulcrum.eval` —— 回放攻击样例集,产出 P0 主结果表 + JSON 报告(对应赛题目标④)。

用法:python -m fulcrum.eval [--dataset 样例集.jsonl] [--out 报告.json]
默认样例集 samples/eval/govoffice.jsonl;默认报告写 docs/eval/results/latest.json。
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..app import build_pipeline
from .dataset import load_dataset
from .metrics import compute
from .report import (
    build_markdown_report,
    build_report,
    format_attack_breakdown,
    format_main_table,
)
from .runner import run_dataset

_DEFAULT_DATASET = "samples/eval/corpus"
_DEFAULT_OUT = "docs/eval/results/latest.json"
_DEFAULT_POLICY = "data/policies/gov_demo.yml"
_VERSION_FILE = "samples/eval/corpus/VERSION"


# 评测管线装配:真实检测(keyword_rules)+ 策略(默认 gov_demo,可 --policy 切换)+ fake 模型。
# 工具级样例均为高危→策略阻断,故工具槽位用 echo 即可,无需注册全部业务工具。
def _eval_config(policy_path: str) -> dict[str, Any]:
    return {
        "labeler": "passthrough",
        "detectors": ["keyword_rules", "manifest_guard"],
        "attributor": "evidence",
        "risk_scorer": "heuristic",
        "chain_analyzer": "noop",
        "policy": "yaml",
        "options": {"yaml": {"path": policy_path}},
        "executor": "echo",
        "tools": ["echo"],
        "model": "fake",
        "audit": "memory",
    }


# 模块级默认装配(gov_demo):供测试与外部 import 复用,等价 _eval_config(_DEFAULT_POLICY)。
_EVAL_CONFIG: dict[str, Any] = _eval_config(_DEFAULT_POLICY)


def _corpus_version() -> str:
    p = Path(_VERSION_FILE)
    return p.read_text(encoding="utf-8").strip() if p.exists() else "dev"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fulcrum.eval", description="枢衡评测:样例回放出分")
    parser.add_argument(
        "--dataset", default=_DEFAULT_DATASET, help="样例集 JSONL 路径或目录(目录递归合并)"
    )
    parser.add_argument("--out", default=_DEFAULT_OUT, help="JSON 报告输出路径")
    parser.add_argument(
        "--policy", default=_DEFAULT_POLICY, help="策略文件路径(gov_demo / default)"
    )
    args = parser.parse_args(argv)

    try:
        samples = load_dataset(args.dataset)
    except (FileNotFoundError, ValueError) as exc:
        print(f"错误:{exc}", file=sys.stderr)
        return 3

    pipeline = build_pipeline(_eval_config(args.policy))
    results = asyncio.run(run_dataset(pipeline, samples))
    metrics = compute(results)

    print(format_main_table(metrics))
    print()
    print(format_attack_breakdown(metrics))

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    report = build_report(metrics, results, dataset=args.dataset)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    # 标准测试报告(md 记分卡):每次跑都产出,统计各项标准数据(plan 08 §6)。
    md_path = out.with_suffix(".md")
    md = build_markdown_report(
        metrics,
        results,
        dataset=args.dataset,
        policy=args.policy,
        version=_corpus_version(),
        generated_at=datetime.now(UTC).astimezone().strftime("%Y-%m-%d %H:%M %Z"),
    )
    md_path.write_text(md, encoding="utf-8")
    print(f"\n标准测试报告(记分卡)已写入:{md_path}")
    print(f"完整报告(逐样例明细 JSON)已写入:{out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
