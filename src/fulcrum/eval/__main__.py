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
    format_gate_breakdown,
    format_main_table,
)
from .runner import run_dataset

_DEFAULT_DATASET = "samples/eval/corpus"
_DEFAULT_OUT = "docs/eval/results/latest.json"
_DEFAULT_POLICY = "data/policies/gov_demo.yml"
_VERSION_FILE = "samples/eval/corpus/VERSION"


# 评测管线装配:真实检测(keyword_rules)+ 策略(默认 gov_demo,可 --policy 切换)+ fake 模型。
# 工具级样例均为高危→策略阻断,故工具槽位用 echo 即可,无需注册全部业务工具。
# chain_analyzer 用生产同款 `sequence`(而非 noop)——让评测真正覆盖「敏感读取→对外发送」
# 跨步外泄链(配合链式样例);对单步样本无影响(trace 仅一步,链分析器不出 finding)。
def _eval_config(policy_path: str) -> dict[str, Any]:
    return {
        "labeler": "passthrough",
        "detectors": ["keyword_rules", "manifest_guard", "disclosure_egress"],
        "attributor": "evidence",
        "risk_scorer": "heuristic",
        "chain_analyzer": "sequence",
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


def _write_report(
    metrics: dict[str, Any],
    results: list[Any],
    dataset: str,
    policy: str,
    out_path: str,
) -> dict[str, Any]:
    """把一次评测的指标/明细写成 JSON 报告 + md 记分卡,返回报告 dict。"""
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    report = build_report(metrics, results, dataset=dataset)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    md = build_markdown_report(
        metrics,
        results,
        dataset=dataset,
        policy=policy,
        version=_corpus_version(),
        generated_at=datetime.now(UTC).astimezone().strftime("%Y-%m-%d %H:%M %Z"),
    )
    out.with_suffix(".md").write_text(md, encoding="utf-8")
    return report


def run_and_write(
    dataset: str = _DEFAULT_DATASET,
    policy: str = _DEFAULT_POLICY,
    out_path: str = _DEFAULT_OUT,
) -> dict[str, Any]:
    """回放样例集 → 写 JSON 报告 + md 记分卡 → 返回报告 dict(同步;内部 `asyncio.run`)。

    CLI(`main`)与控制台「发起评测」(组装层 `EvalRunner` 经 `asyncio.to_thread`)共用此函数,
    保证两条入口出分口径、产物路径完全一致。内部 `asyncio.run`,故调用方须在**非事件循环线程**里跑。
    """
    samples = load_dataset(dataset)
    pipeline = build_pipeline(_eval_config(policy))
    results = asyncio.run(run_dataset(pipeline, samples))
    return _write_report(compute(results), results, dataset, policy, out_path)


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
    print()
    print(format_gate_breakdown(metrics))

    _write_report(metrics, results, args.dataset, args.policy, args.out)
    print(f"\n标准测试报告(记分卡)已写入:{Path(args.out).with_suffix('.md')}")
    print(f"完整报告(逐样例明细 JSON)已写入:{args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
