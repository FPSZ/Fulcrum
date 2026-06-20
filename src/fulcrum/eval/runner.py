"""样例回放 —— 把每条样例过真实枢衡管线,记录实处置 + 审计校验结果。

链式样例 → 同一会话顺序回放多步 `evaluate_intent`(让 `sequence` 链分析器看见跨步轨迹);
输入级样例 → `pipeline.screen_input`(检测→入口闸门);工具级样例 → `pipeline.evaluate_intent`
(策略判定);出口级样例 → `pipeline.screen_output`(检测→出口闸门,量化回复防泄露)。
每条用独立 session_id 跑,以便逐条核验 hash-chain 与审计完整性。
"""

from __future__ import annotations

import time

from pydantic import BaseModel

from ..capabilities.detectors.keyword_rules import KeywordRuleDetector
from ..capabilities.labelers.role_trust import RoleTrustLabeler
from ..core.domain import Context, Message, ModelRequest, ToolIntent
from ..core.pipeline import SecurityPipeline
from .dataset import EvalSample

# 非 allow 的处置都视为"已管控/未放行"(拦截 / 审核 / 净化)。
_HELD = frozenset({"block", "approve", "sanitize"})
# 强处置(对应指标体系 §4.2"高危动作执行 block 或 require_approval")。
_STRONG = frozenset({"block", "approve"})
# 处置强度序:链式样例取多步里"最强"的一档作为整条链的判定(任一步阻断即整链阻断)。
_DISPOSITION_RANK = {"allow": 0, "sanitize": 1, "approve": 2, "block": 3}

# 溯源归因(评测层):用 role_trust 抽嵌入源 + 检测器,按命中分对来源类型排序。
# 不走 gateway.screen_input(它按前门威胁模型把整条标 UNTRUSTED USER,不抽源),故单列。
_ATTR_LABELER = RoleTrustLabeler()
_ATTR_DETECTOR = KeywordRuleDetector()


def _attribute_sources(text: str) -> list[str]:
    """按命中分降序返回来源类型名(document/webpage/retrieval/memory/…),供 hit@k 计算。"""
    req = ModelRequest(session_id="attr", messages=[Message(role="user", content=text)])
    spans = _ATTR_LABELER.label(req)
    findings = _ATTR_DETECTOR.detect(spans, Context(session_id="attr"))
    best: dict[str, float] = {}
    for f in findings:
        st = f.evidence.get("source_type")
        if st is None:
            continue
        name = st.name.lower() if hasattr(st, "name") else str(st).lower()
        best[name] = max(best.get(name, 0.0), f.score)
    return [name for name, _ in sorted(best.items(), key=lambda kv: kv[1], reverse=True)]


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
    # —— 标准化分类(透传自样本,供覆盖矩阵/差距清单)——
    owasp: str = ""
    mitre_atlas: str = ""
    severity: str = ""
    technique: str = ""
    # —— 主表补齐:网关侧延迟 + 溯源命中(对齐指标体系 §5.1/§7.2)——
    latency_ms: float = 0.0
    has_trace_gold: bool = False  # 是否带 expected_trace_source 金标准
    trace_hit_1: bool = False
    trace_hit_3: bool = False

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


async def _replay_chain(
    pipeline: SecurityPipeline, sid: str, sample: EvalSample
) -> tuple[str, str]:
    """同一会话顺序回放链式样例的每步工具意图,返回(最强处置, 该步理由)。

    复用单个 Context,使 `request_trace` / `tool_returns` 跨步累积 —— `sequence` 链分析器
    据此在收口的"对外发送"步识别外泄链。整条链取多步中**最强**处置(任一步阻断即判阻断),
    对齐"链上任何一步被管控,这次外泄企图即未得逞"的语义。
    """
    ctx = Context(session_id=sid)
    predicted, reason = "allow", ""
    for step in sample.steps or []:
        intent = ToolIntent(session_id=sid, tool_name=step.target_tool, arguments=step.tool_args)
        outcome = await pipeline.evaluate_intent(intent, ctx)
        decision = outcome.decision.decision.value
        if _DISPOSITION_RANK[decision] >= _DISPOSITION_RANK[predicted]:
            predicted, reason = decision, outcome.decision.reason
    return predicted, reason


async def run_sample(pipeline: SecurityPipeline, sample: EvalSample) -> SampleResult:
    sid = f"eval-{sample.sample_id}"
    t0 = time.perf_counter()
    if sample.is_chain_sample:
        predicted, reason = await _replay_chain(pipeline, sid, sample)
    elif sample.is_tool_sample:
        ctx = Context(session_id=sid)
        intent = ToolIntent(
            session_id=sid, tool_name=sample.target_tool or "", arguments=sample.tool_args
        )
        outcome = await pipeline.evaluate_intent(intent, ctx)
        predicted = outcome.decision.decision.value
        reason = outcome.decision.reason
    elif sample.is_output_sample:
        verdict = await pipeline.screen_output(sid, sample.reply or "")
        predicted = verdict.decision.value
        reason = verdict.reason
    else:
        verdict = await pipeline.screen_input(sid, sample.input or "")
        predicted = verdict.decision.value
        reason = verdict.reason
    latency_ms = (time.perf_counter() - t0) * 1000.0

    # 溯源命中:仅对带 expected_trace_source 金标准的输入级样本计算(链式/工具/出口样本不计)。
    has_gold = bool(
        sample.expected_trace_source
        and not sample.is_chain_sample
        and not sample.is_tool_sample
        and not sample.is_output_sample
    )
    hit1 = hit3 = False
    if has_gold:
        ranked = _attribute_sources(sample.input or "")
        gold = sample.expected_trace_source
        hit1 = bool(ranked) and ranked[0] == gold
        hit3 = gold in ranked[:3]

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
        owasp=sample.owasp,
        mitre_atlas=sample.mitre_atlas,
        severity=sample.severity,
        technique=sample.technique,
        latency_ms=round(latency_ms, 3),
        has_trace_gold=has_gold,
        trace_hit_1=hit1,
        trace_hit_3=hit3,
    )


async def run_dataset(pipeline: SecurityPipeline, samples: list[EvalSample]) -> list[SampleResult]:
    """顺序回放(确定性、可复现;并发与延迟测量留待 P1)。"""
    return [await run_sample(pipeline, s) for s in samples]
