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
MEDIUM_AT = 0.4

# 载荷分片防御:攻击者把一段注入摊到**多个不同来源**(如文档+网页+记忆各夹带一截),
# 每条都压在复核阈下(各 < REVIEW_AT),仅取 max(score) 会整体放行。若有 ≥ 此数目的
# **不同来源**各自命中中风险及以上,视为分布式规避,效力升至复核档(交人工);但**不凭
# 聚合单独升到拦截**(保守,仅升一档到 review,避免误伤)。单来源单消息不受影响。
_SPLIT_MIN_SOURCES = 3


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


def _distinct_risky_sources(findings: list[Finding]) -> int:
    """命中中风险及以上的**不同来源**数(按 finding 证据里的 source_id 去重)。

    无 source_id 的 finding(链/合成类)不计入——分片规避针对的是多源夹带。
    """
    return len(
        {
            f.evidence.get("source_id")
            for f in findings
            if f.score >= MEDIUM_AT and f.evidence.get("source_id") is not None
        }
    )


def _effective_score(findings: list[Finding], max_score: float) -> float:
    """分布式分片规避的等效风险:多源各压阈下 → 升至复核档;否则维持 max。

    仅在 max 未达拦截阈时介入,且最高升到 REVIEW_AT(交人工),不凭聚合直接拦截。
    """
    if max_score < BLOCK_AT and _distinct_risky_sources(findings) >= _SPLIT_MIN_SOURCES:
        return max(max_score, REVIEW_AT)
    return max_score


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
    eff = _effective_score(findings, score)
    level = _risk_level(eff)
    kinds = sorted({f.kind for f in findings})
    label = "、".join(kinds)

    if eff >= BLOCK_AT:
        decision = Disposition.BLOCK
        reason = f"命中高危输入风险({label}),已拦截,不转发企业智能体。"
    elif eff >= REVIEW_AT:
        decision = Disposition.APPROVE
        reason = (
            f"多来源分散夹带({label}),综合判定挂起人工审核,暂不转发。"
            if eff > score
            else f"命中可疑输入({label}),已挂起人工审核,暂不转发。"
        )
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


def screen_output(findings: list[Finding]) -> GateVerdict:
    """出口闸门:对**企业智能体的回复**判敏感/危险内容 → 放行 / 标注复核 / 拦截。

    与 `screen`(入口)同阈值、同 Finding 来源,只是处置语义换成"回复要不要回给用户":
        block    → 回复疑似含敏感数据外泄,拦截不回传(打码)。
        sanitize → 回复夹带的**唯一**风险是可机械打码的结构化敏感量(pii_leak),
                   且在复核档(未到拦截阈)→ 脱敏后回传:既不漏明文,也不白丢整条回复。
        approve  → 回复可疑(含打码救不了的风险,如外联措辞),标注待人工复核。
        allow    → 回复正常,放行回传。
    """
    if not findings:
        return GateVerdict(
            decision=Disposition.ALLOW,
            risk_level=RiskLevel.LOW,
            reason="回复未命中敏感/危险内容,放行回传。",
            max_score=0.0,
            top_kind=None,
            findings=[],
        )

    top = max(findings, key=lambda f: f.score)
    score = top.score
    eff = _effective_score(findings, score)
    level = _risk_level(eff)
    kinds = {f.kind for f in findings}
    label = "、".join(sorted(kinds))

    if eff >= BLOCK_AT:
        decision = Disposition.BLOCK
        reason = f"回复命中高危内容({label}),疑似敏感数据外泄,已拦截不回传。"
    elif eff >= REVIEW_AT and kinds == {"pii_leak"}:
        # 复核档,且全部风险都是可打码的结构化敏感量 → 脱敏回传,无需人工挡件。
        decision = Disposition.SANITIZE
        reason = f"回复夹带结构化敏感量({label}),已脱敏后回传。"
    elif eff >= REVIEW_AT:
        decision = Disposition.APPROVE
        reason = f"回复命中可疑内容({label}),标注待人工复核。"
    else:
        decision = Disposition.ALLOW
        reason = f"回复风险较低({label}),放行回传。"

    return GateVerdict(
        decision=decision,
        risk_level=level,
        reason=reason,
        max_score=score,
        top_kind=top.kind,
        findings=findings,
    )
