"""P6 融合参数调优 —— 在 ML 环境实跑冻结语料,量 ML 概率分布 + 阈值/封顶/融合策略 delta。

回答 doc 09 §5 P6 待办:"在 ML 环境实跑冻结语料量召回/FPR delta 并调阈值/封顶"。
口径与 run_bench.py 一致(库内输入级子集,按金标准算召回/FPR)。结论写入 p6-fusion-tuning.md。

依赖 transformers/torch(本仓默认无,见 doc 08 §10);缺失即报错退出(本脚本是 ML 环境专用工具)。
用法:HF_ENDPOINT=https://hf-mirror.com python samples/eval/benchmarks/tune_p6.py
"""

from __future__ import annotations

import sys

sys.path.insert(0, "src")

from fulcrum.capabilities.detectors.keyword_rules import KeywordRuleDetector  # noqa: E402
from fulcrum.core.domain import Context, SourceSpan, SourceType, TrustLevel  # noqa: E402
from fulcrum.eval.dataset import load_dataset  # noqa: E402

CORPUS = "samples/eval/corpus"
REVIEW_AT = 0.6  # screen_input 挂复核阈(core/gateway.REVIEW_AT)
MODEL = "protectai/deberta-v3-base-prompt-injection-v2"
_CTX = Context(session_id="tune")
_DET = KeywordRuleDetector()


def input_subset():
    return [
        s
        for s in load_dataset(CORPUS)
        if s.input is not None and s.target_tool is None and s.reply is None
    ]


def _rule_max(text: str) -> float:
    """规则检测器对该文本的最高分(按输入闸门口径:UNTRUSTED USER)。"""
    span = SourceSpan(
        source_type=SourceType.USER, trust_level=TrustLevel.UNTRUSTED, content_hash="x", excerpt=text
    )
    return max((f.score for f in _DET.detect([span], _CTX)), default=0.0)


def _ascii_ratio(text: str) -> float:
    return sum(ord(c) < 128 for c in text) / len(text) if text else 1.0


def _make_backend():
    """共享一次加载的 HF 后端,(text)->攻击概率,与 ml_classifier._load_default_backend 同口径。"""
    from transformers import pipeline

    clf = pipeline("text-classification", model=MODEL, truncation=True, max_length=512)
    attack = {"INJECTION", "JAILBREAK", "MALICIOUS", "LABEL_1"}

    def score(text: str) -> float:
        out = clf(text)[0]
        prob = float(out["score"])
        return prob if str(out["label"]).upper() in attack else 1.0 - prob

    return score


def main() -> int:
    samples = input_subset()
    backend = _make_backend()
    rows = [
        {
            "id": s.sample_id,
            "mal": s.ground_truth_malicious,
            "rmax": _rule_max(s.input or ""),
            "ml": backend(s.input or ""),
            "ascii": _ascii_ratio(s.input or ""),
        }
        for s in samples
    ]
    mal = [r for r in rows if r["mal"]]
    ben = [r for r in rows if not r["mal"]]
    nm, nb = len(mal), len(ben)
    print(f"输入子集:恶意 {nm} · 良性 {nb}")

    def quantiles(vals):
        v = sorted(vals)
        return [round(v[int(q * (len(v) - 1))], 3) for q in (0, 0.25, 0.5, 0.75, 1)]

    print("\n=== A. ML 攻击概率分布(0/.25/.5/.75/1 分位)===")
    print("  恶意:", quantiles(r["ml"] for r in mal))
    print("  良性:", quantiles(r["ml"] for r in ben))

    print("\n=== B. ML 单跑:阈值 × 召回/FPR(模型输出近二值 → FPR 不随阈值变)===")
    print(f"  {'阈值':>5} {'召回':>8} {'FPR':>8}")
    for th in (0.5, 0.7, 0.8, 0.9, 0.95, 0.99):
        rec = sum(r["ml"] >= th for r in mal) / nm
        fpr = sum(r["ml"] >= th for r in ben) / nb
        print(f"  {th:>5} {rec * 100:>7.1f}% {fpr * 100:>7.1f}%")

    print("\n=== C. 融合策略 × 召回(held)/FPR(阈值 0.9)===")
    th = 0.9
    rule_held = lambda r: r["rmax"] >= REVIEW_AT  # noqa: E731
    ml_hit = lambda r: r["ml"] >= th  # noqa: E731
    policies = {
        "baseline(仅规则)": rule_held,
        "独立 ML(cap≥0.6,现默认)": lambda r: rule_held(r) or ml_hit(r),
        "确认增强(规则有信号 AND ML)": lambda r: rule_held(r) or (r["rmax"] > 0 and ml_hit(r)),
        "英文门(ascii≥0.8 才认 ML)": lambda r: rule_held(r) or (r["ascii"] >= 0.8 and ml_hit(r)),
    }
    print(f"  {'策略':<30} {'召回':>9} {'FPR':>9}")
    for name, fn in policies.items():
        rec = sum(fn(r) for r in mal) / nm
        fpr = sum(fn(r) for r in ben) / nb
        print(f"  {name:<30} {rec * 100:>8.1f}% {fpr * 100:>8.1f}%")

    saved = [r for r in mal if not rule_held(r) and ml_hit(r)]
    print(f"\n=== D. ML 救回(规则零信号)的恶意 {len(saved)} 条;rmax>0 的仅 "
          f"{sum(r['rmax'] > 0 for r in saved)} 条 → 召回与 FPR 不可分 ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
