"""输入闸门 —— 把检测器**已产出**的风险结论映射为前置处置动作(拦截/审核/放行)。

定位:这是**编排**,不是判断算法。判断仍由 detectors(keyword_rules 等)完成;
本模块只读取它们产出的 Finding.score / severity,按阈值决定"在转发给企业智能体之前
要不要拦、要不要送人工审核"。阈值与检测器自身的 severity 分档对齐(见 keyword_rules._severity)。

    max_score ≥ BLOCK_AT(critical)   → BLOCK   拦截:不转发,直接挡回
    max_score ≥ REVIEW_AT(high)      → APPROVE 审核:挂起待人工放行,暂不转发
    否则                              → ALLOW   放行:转发给企业智能体

替换/调参只动这里,检测算法零改动。
"""

from __future__ import annotations

from dataclasses import dataclass

from .domain import Disposition, Finding, RiskLevel

# 与 keyword_rules._severity 的分档对齐:critical=0.8 / high=0.6 / medium=0.4。
BLOCK_AT = 0.8
REVIEW_AT = 0.6


@dataclass(slots=True)
class GateVerdict:
    """输入闸门结论(供网关决定转发与否 + 写审计 + 回前端)。"""

    decision: Disposition
    risk_level: RiskLevel
    reason: str
    max_score: float
    top_kind: str | None
    findings: list[Finding]

    @property
    def forwarded(self) -> bool:
        """仅 ALLOW 才会被转发给企业智能体。"""
        return self.decision == Disposition.ALLOW


def _risk_level(score: float) -> RiskLevel:
    if score >= 0.8:
        return RiskLevel.CRITICAL
    if score >= 0.6:
        return RiskLevel.HIGH
    if score >= 0.4:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def screen(findings: list[Finding]) -> GateVerdict:
    """读取检测结论 → 给出拦截/审核/放行。无命中即放行。"""
    if not findings:
        return GateVerdict(
            decision=Disposition.ALLOW,
            risk_level=RiskLevel.LOW,
            reason="未命中任何输入风险规则,放行转发。",
            max_score=0.0,
            top_kind=None,
            findings=[],
        )

    top = max(findings, key=lambda f: f.score)
    score = top.score
    level = _risk_level(score)
    kinds = sorted({f.kind for f in findings})
    label = "、".join(kinds)

    if score >= BLOCK_AT:
        decision = Disposition.BLOCK
        reason = f"命中高危输入风险({label}),已拦截,不转发企业智能体。"
    elif score >= REVIEW_AT:
        decision = Disposition.APPROVE
        reason = f"命中可疑输入({label}),已挂起人工审核,暂不转发。"
    else:
        decision = Disposition.ALLOW
        reason = f"输入风险较低({label}),放行转发。"

    return GateVerdict(
        decision=decision,
        risk_level=level,
        reason=reason,
        max_score=score,
        top_kind=top.kind,
        findings=findings,
    )
