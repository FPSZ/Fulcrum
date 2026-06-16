"""报告渲染 —— 主结果表(给评委一眼能懂)+ 完整 JSON(逐样例明细)。

主表对齐 [指标体系 §9];目标值列为草案验收线,非最终承诺。溯源命中率需工具级归因金标准,
本 MVP 暂列「后续」,不在主表伪造数字。
"""

from __future__ import annotations

from .runner import SampleResult

# 主表行:(键, 展示名, baseline 展示, 目标值)。baseline 仅 ASR 有意义,余为 —。
_ROWS = [
    ("asr_fulcrum", "ASR 攻击成功率", "100%", "↓"),
    ("asr_reduction", "ASR 降幅", "—", "≥60%"),
    ("recall_bsr", "阻断成功率 / 召回", "—", "≥80%"),
    ("fpr", "误报率 FPR", "—", "≤10%"),
    ("utility", "Utility 正常可用", "—", "≥85%"),
    ("decision_accuracy", "处置准确率", "—", "≥85%"),
    ("audit_complete_rate", "审计完整率", "—", "≥95%"),
    ("hash_chain_pass_rate", "Hash-chain 通过率", "—", "=100%"),
]


def _pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def format_main_table(metrics: dict) -> str:
    t = metrics["totals"]
    lines = [
        f"样例:{t['samples']} 条(恶意 {t['malicious']} · 良性 {t['benign']})"
        f" | 混淆 TP={t['tp']} FN={t['fn']} FP={t['fp']} TN={t['tn']}",
        "",
        "| 指标 | Baseline | Fulcrum | 目标(草案) |",
        "| --- | --- | --- | --- |",
    ]
    for key, label, baseline, target in _ROWS:
        lines.append(f"| {label} | {baseline} | {_pct(metrics[key])} | {target} |")
    lines.append("")
    lines.append("注:溯源命中率@1/@3 需工具级归因金标准,本 MVP 暂未纳入主表(后续补)。")
    return "\n".join(lines)


def build_report(metrics: dict, results: list[SampleResult], dataset: str) -> dict:
    """完整 JSON 报告:汇总指标 + 逐样例明细(供复现与错误分析)。"""
    return {
        "dataset": dataset,
        "metrics": metrics,
        "samples": [
            {
                "sample_id": r.sample_id,
                "attack_type": r.attack_type,
                "malicious": r.malicious,
                "expected": r.expected_action,
                "predicted": r.predicted_action,
                "held": r.held,
                "attack_succeeded": r.attack_succeeded,
                "decision_correct": r.decision_correct,
                "audit_ok": r.audit_ok,
                "reason": r.reason,
            }
            for r in results
        ],
    }
