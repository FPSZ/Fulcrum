"""样例回放 —— 把每条样例过真实枢衡管线,记录实处置 + 审计校验结果。

输入级样例 → `pipeline.screen_input`(检测→入口闸门);工具级样例 → `pipeline.evaluate_intent`
(策略判定);出口级样例 → `pipeline.screen_output`(检测→出口闸门,量化回复防泄露)。
每条用独立 session_id 跑,以便逐条核验 hash-chain 与审计完整性。
"""

from __future__ import annotations

import hashlib

from pydantic import BaseModel, Field

from ..core.domain import Context, SourceSpan, SourceType, ToolIntent, TrustLevel
from ..core.pipeline import SecurityPipeline
from .dataset import EvalSample, EvalSource

# 非 allow 的处置都视为"已管控/未放行"(拦截 / 审核 / 净化)。
_HELD = frozenset({"block", "approve", "sanitize"})


def _to_span(s: EvalSource) -> SourceSpan:
    return SourceSpan(
        source_id=s.source_id,
        source_type=SourceType(s.source_type),
        trust_level=TrustLevel(s.trust_level),
        content_hash=hashlib.sha256(s.content.encode("utf-8")).hexdigest(),
        excerpt=s.content,
    )


class SampleResult(BaseModel):
    """单条样例的回放结果(供指标计算)。"""

    sample_id: str
    attack_type: str
    malicious: bool
    expected_action: str
    predicted_action: str
    reason: str = ""
    audit_ok: bool = False  # hash-chain 校验通过
    event_count: int = 0
    expected_trace_source: str | None = None  # 金标归因来源(有则计入溯源命中率)
    attributed_sources: list[str] = Field(default_factory=list)  # 实际归因候选(按置信度降序)

    @property
    def held(self) -> bool:
        """是否被管控(未直接放行)。"""
        return self.predicted_action in _HELD

    @property
    def attack_succeeded(self) -> bool:
        """攻击成功 = 恶意样例被直接放行(approve/sanitize 为挂起,不算成功)。"""
        return self.malicious and self.predicted_action == "allow"

    @property
    def decision_correct(self) -> bool:
        return self.predicted_action == self.expected_action


async def run_sample(pipeline: SecurityPipeline, sample: EvalSample) -> SampleResult:
    sid = f"eval-{sample.sample_id}"
    attributed: list[str] = []
    if sample.is_tool_sample:
        ctx = Context(session_id=sid)
        ctx.spans = [_to_span(s) for s in sample.sources]  # 多源上下文供归因比对
        intent = ToolIntent(
            session_id=sid, tool_name=sample.target_tool or "", arguments=sample.tool_args
        )
        outcome = await pipeline.evaluate_intent(intent, ctx)
        predicted = outcome.decision.decision.value
        reason = outcome.decision.reason
        attributed = list(outcome.intent.derived_from_sources)  # 已按置信度降序
    elif sample.is_output_sample:
        verdict = await pipeline.screen_output(sid, sample.reply or "")
        predicted = verdict.decision.value
        reason = verdict.reason
    else:
        verdict = await pipeline.screen_input(sid, sample.input or "")
        predicted = verdict.decision.value
        reason = verdict.reason

    events = await pipeline.audit.events(sid)
    audit_ok = await pipeline.audit.verify_chain(sid)
    return SampleResult(
        sample_id=sample.sample_id,
        attack_type=sample.attack_type,
        malicious=sample.ground_truth_malicious,
        expected_action=sample.expected_action,
        predicted_action=predicted,
        reason=reason,
        audit_ok=audit_ok,
        event_count=len(events),
        expected_trace_source=sample.expected_trace_source,
        attributed_sources=attributed,
    )


async def run_dataset(pipeline: SecurityPipeline, samples: list[EvalSample]) -> list[SampleResult]:
    """顺序回放(确定性、可复现;并发与延迟测量留待 P1)。"""
    return [await run_sample(pipeline, s) for s in samples]
