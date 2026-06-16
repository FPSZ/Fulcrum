"""`python -m fulcrum.eval` —— 回放攻击样例集,产出 P0 主结果表 + JSON 报告(对应赛题目标④)。

用法:python -m fulcrum.eval [--dataset 样例集.jsonl] [--out 报告.json]
默认样例集 samples/eval/govoffice.jsonl;默认报告写 docs/eval/results/latest.json。
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from ..app import build_pipeline
from .dataset import load_dataset
from .metrics import compute
from .report import build_report, format_main_table
from .runner import run_dataset

_DEFAULT_DATASET = "samples/eval/govoffice.jsonl"
_DEFAULT_OUT = "docs/eval/results/latest.json"

# 评测管线装配:真实检测(keyword_rules)+ 政务策略(gov_demo)+ fake 模型(评测不接真模型)。
# 工具级样例均为高危→策略阻断,故工具槽位用 echo 即可,无需注册全部业务工具。
_EVAL_CONFIG: dict[str, Any] = {
    "labeler": "passthrough",
    "detectors": ["keyword_rules"],
    "attributor": "evidence",
    "risk_scorer": "heuristic",
    "chain_analyzer": "noop",
    "policy": "yaml",
    "options": {"yaml": {"path": "data/policies/gov_demo.yml"}},
    "executor": "echo",
    "tools": ["echo"],
    "model": "fake",
    "audit": "memory",
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fulcrum.eval", description="枢衡评测:样例回放出分")
    parser.add_argument("--dataset", default=_DEFAULT_DATASET, help="样例集 JSONL 路径")
    parser.add_argument("--out", default=_DEFAULT_OUT, help="JSON 报告输出路径")
    args = parser.parse_args(argv)

    try:
        samples = load_dataset(args.dataset)
    except (FileNotFoundError, ValueError) as exc:
        print(f"错误:{exc}", file=sys.stderr)
        return 3

    pipeline = build_pipeline(_EVAL_CONFIG)
    results = asyncio.run(run_dataset(pipeline, samples))
    metrics = compute(results)

    print(format_main_table(metrics))

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    report = build_report(metrics, results, dataset=args.dataset)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n完整报告(逐样例明细)已写入:{out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
