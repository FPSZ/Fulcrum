"""竞品对标 —— 用冻结的攻击样例库(输入子集)给同类输入防护系统打分。

口径:取库内**输入级**样本(input 置位、无 target_tool/reply),同一批文本喂给各检测器,
按我们的金标准算 检出率(召回)/ FPR / 分桶召回。工具层/出口/供应链是枢衡差异化覆盖、
多数竞品不涉及,单列说明(见 README)。

检测器即插即用:工厂函数 import 失败(未装依赖/模型不可达)→ 跳过并记录原因,不阻断整体。
用法:python samples/eval/benchmarks/run_bench.py [--only fulcrum,protectai] [--out 路径.md]
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, "src")
from fulcrum.eval.dataset import EvalSample, load_dataset  # noqa: E402

CORPUS = "samples/eval/corpus"


def input_subset() -> list[EvalSample]:
    """输入级样本:竞品(输入防护)可判的那批。"""
    return [
        s
        for s in load_dataset(CORPUS)
        if s.input is not None and s.target_tool is None and s.reply is None
    ]


# ---- 检测器工厂:返回 detect(text, sid) -> bool(判为攻击)。import 失败即抛,由上层捕获跳过。----
def _fulcrum():
    from fulcrum.app import build_pipeline
    from fulcrum.eval.__main__ import _EVAL_CONFIG

    pipe = build_pipeline(_EVAL_CONFIG)
    held = {"block", "approve", "sanitize"}

    def detect(text: str, sid: str) -> bool:
        v = asyncio.run(pipe.screen_input(f"bench-{sid}", text))
        return v.decision.value in held

    return detect


def _hf_textcls(model: str, attack_labels: set[str]):
    """通用 HuggingFace 文本分类适配器(deberta 注入/越狱分类器等)。"""
    from transformers import pipeline  # 延迟导入:未装 transformers/torch 则跳过

    clf = pipeline("text-classification", model=model, truncation=True, max_length=512)

    def detect(text: str, sid: str) -> bool:
        label = str(clf(text)[0]["label"]).upper()
        return label in attack_labels

    return detect


def _protectai_deberta():
    return _hf_textcls("protectai/deberta-v3-base-prompt-injection-v2", {"INJECTION", "LABEL_1"})


def _deepset_deberta():
    return _hf_textcls("deepset/deberta-v3-base-injection", {"INJECTION", "LABEL_1"})


def _llama_prompt_guard():
    # 注:Meta Llama-Prompt-Guard-2 为受限模型,需 HF token + 接受许可,否则拉取失败被跳过。
    return _hf_textcls(
        "meta-llama/Llama-Prompt-Guard-2-86M",
        {"LABEL_1", "INJECTION", "JAILBREAK", "MALICIOUS"},
    )


DETECTORS = {
    "fulcrum(枢衡)": _fulcrum,
    "protectai/deberta-v3-base-prompt-injection-v2": _protectai_deberta,
    "deepset/deberta-v3-base-injection": _deepset_deberta,
    "meta/Llama-Prompt-Guard-2-86M": _llama_prompt_guard,
}


def score(detect, samples: list[EvalSample]) -> dict:
    mal = [s for s in samples if s.ground_truth_malicious]
    ben = [s for s in samples if not s.ground_truth_malicious]
    tp = sum(1 for s in mal if detect(s.input or "", s.sample_id))
    fp = sum(1 for s in ben if detect(s.input or "", s.sample_id))
    by: dict[str, list[int]] = {}
    for s in mal:
        d = 1 if detect(s.input or "", s.sample_id) else 0
        by.setdefault(s.attack_type, [0, 0])
        by[s.attack_type][0] += d
        by[s.attack_type][1] += 1
    return {
        "malicious": len(mal),
        "benign": len(ben),
        "recall": tp / len(mal) if mal else 0.0,
        "fpr": fp / len(ben) if ben else 0.0,
        "by_type": {k: v[0] / v[1] for k, v in by.items()},
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="竞品对标:库输入子集 × 各检测器")
    ap.add_argument("--only", default="", help="逗号分隔的检测器名子串过滤")
    ap.add_argument("--out", default="samples/eval/benchmarks/scorecard.md")
    args = ap.parse_args(argv)

    samples = input_subset()
    types = sorted({s.attack_type for s in samples if s.ground_truth_malicious})
    rows, skipped = {}, {}
    for name, factory in DETECTORS.items():
        if args.only and not any(o.strip() in name for o in args.only.split(",")):
            continue
        try:
            detect = factory()
            print(f"[run] {name} …", flush=True)
            rows[name] = score(detect, samples)
        except Exception as exc:  # noqa: BLE001 —— 依赖/模型不可达即跳过并记录
            skipped[name] = f"{type(exc).__name__}: {exc}"
            print(f"[skip] {name}: {skipped[name]}", flush=True)

    lines = [
        "# 竞品对标记分卡 · 输入子集",
        "",
        f"- 数据集:`{CORPUS}`(v1.0.0 冻结)· 输入子集 {len(samples)} 条"
        f"(恶意 {sum(s.ground_truth_malicious for s in samples)} · "
        f"良性 {sum(not s.ground_truth_malicious for s in samples)})",
        "- 口径:同一批输入文本,各检测器输出 检出/放行,按金标准算检出率(召回)+FPR。",
        "- 范围说明:工具调用管控/出口防泄露/供应链为枢衡差异化覆盖,多数竞品仅做输入侧,故对比限输入子集。",
        "",
        "## 总览",
        "",
        "| 系统 | 检出率(召回) | FPR | 恶意 | 良性 |",
        "| --- | --- | --- | --- | --- |",
    ]
    for name, m in rows.items():
        lines.append(
            f"| {name} | {m['recall'] * 100:.1f}% | {m['fpr'] * 100:.1f}% | {m['malicious']} | {m['benign']} |"
        )
    lines += ["", "## 分桶检出率(恶意)", "", "| 系统 | " + " | ".join(types) + " |",
              "| --- |" + " --- |" * len(types)]
    for name, m in rows.items():
        cells = " | ".join(f"{m['by_type'].get(t, 0.0) * 100:.0f}%" for t in types)
        lines.append(f"| {name} | {cells} |")
    if skipped:
        lines += ["", "## 未运行(依赖/模型不可达)", ""]
        for name, why in skipped.items():
            lines.append(f"- {name}:{why}")
    lines += ["", "---", "*由 run_bench.py 生成。受限模型需 HF token+接受许可方可拉取。*"]

    out = Path(args.out)
    out.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))
    print(f"\n记分卡已写入:{out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
