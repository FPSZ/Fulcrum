"""`python -m fulcrum.eval` —— 回放攻击样例集,产出 P0 主结果表 + JSON 报告(对应赛题目标④)。

用法:python -m fulcrum.eval [--dataset 样例集.jsonl] [--out 报告.json]
默认样例集 samples/eval/corpus(目录递归合并);默认报告写 docs/eval/results/latest.json。
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
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


# 评测管线装配:检测器集与生产 fulcrum.yml 对齐(keyword_rules + secret_egress + manifest_guard
# + disclosure_egress),策略默认 gov_demo(可 --policy 切换)+ fake 模型——评测的是真实上线的那套
# 检测组合,而非裁剪过的子集。工具级样例均为高危→策略阻断,故工具槽位用 echo 即可,
# 无需注册全部业务工具。
# chain_analyzer 用生产同款 `sequence`(而非 noop)——让评测真正覆盖「敏感读取→对外发送」
# 跨步外泄链(配合链式样例);对单步样本无影响(trace 仅一步,链分析器不出 finding)。
def _judge_opts_from_env() -> dict[str, Any]:
    """从统一 env(LLM_BASE/LLM_MODEL/LLM_API_KEY/LLM_NO_THINK)装配 llm_judge 检测器参数。

    与 run_suite/bench 同口径:本地 air-gapped 自托管端点(数据不出域),推理模型关思考直出裁决。
    键名须对齐 LlmJudgeDetector 构造参数(endpoint/model/api_key/extra_body)。
    """
    no_think = os.environ.get("LLM_NO_THINK", "0") == "1"
    return {
        "endpoint": os.environ.get("LLM_BASE", "http://127.0.0.1:8123/v1"),
        "model": os.environ.get("LLM_MODEL", "qwen3-8b"),
        "api_key": os.environ.get("LLM_API_KEY", ""),
        "extra_body": {"chat_template_kwargs": {"enable_thinking": False}} if no_think else {},
    }


def _eval_config(policy_path: str, *, judge: str | None = None) -> dict[str, Any]:
    """装配评测管线。judge: None=纯规则基线;"full"=全量 LLM-judge;"cascade"=灰区级联。

    full —— keyword_rules 之外追加 llm_judge,每条都判(测召回上限,延迟最高)。
    cascade —— 用 injection_cascade 取代 keyword_rules:规则先出分,仅灰区落 judge(在线降延迟)。
    端点不可达 → judge 自动降级,确定性规则照常,绝不 fail-open。
    """
    options: dict[str, Any] = {"yaml": {"path": policy_path}}
    egress = ["secret_egress", "manifest_guard", "disclosure_egress"]
    if judge == "cascade":
        detectors = ["injection_cascade", *egress]
        options["injection_cascade"] = {
            "gray_low": float(os.environ.get("JUDGE_GRAY_LOW", "0.0")),
            "gray_high": float(os.environ.get("JUDGE_GRAY_HIGH", "0.6")),
            "judge": _judge_opts_from_env(),
        }
    elif judge == "full":
        detectors = ["keyword_rules", *egress, "llm_judge"]
        options["llm_judge"] = _judge_opts_from_env()
    else:
        detectors = ["keyword_rules", *egress]
    return {
        "labeler": "passthrough",
        "detectors": detectors,
        "attributor": "evidence",
        "risk_scorer": "heuristic",
        "chain_analyzer": "sequence",
        "policy": "yaml",
        "options": options,
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
    parser.add_argument(
        "--judge",
        choices=["full", "cascade"],
        default=None,
        help="LLM-judge 语义层:full=全量(每条都判);cascade=灰区级联(仅规则拿不准的落 judge)。"
        "端点经 LLM_BASE/LLM_MODEL/LLM_API_KEY/LLM_NO_THINK 注入;灰区阈值经 JUDGE_GRAY_LOW/HIGH",
    )
    args = parser.parse_args(argv)

    try:
        samples = load_dataset(args.dataset)
    except (FileNotFoundError, ValueError) as exc:
        print(f"错误:{exc}", file=sys.stderr)
        return 3

    pipeline = build_pipeline(_eval_config(args.policy, judge=args.judge))
    results = asyncio.run(run_dataset(pipeline, samples))
    metrics = compute(results)

    print(format_main_table(metrics))
    print()
    print(format_attack_breakdown(metrics))
    print()
    print(format_gate_breakdown(metrics))

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    report = build_report(metrics, results, dataset=args.dataset)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    # 标准测试报告(md 记分卡):每次跑都产出,统计各项标准数据(plan 08 §6)。
    # json 落在 json/ 子目录时,md 平级写到 markdown/(json 与 md 分目录,命名一致)。
    if out.parent.name == "json":
        md_dir = out.parent.parent / "markdown"
        md_dir.mkdir(parents=True, exist_ok=True)
        md_path = md_dir / f"{out.stem}.md"
    else:
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
