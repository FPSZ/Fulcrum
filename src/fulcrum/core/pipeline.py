"""安全管线编排(应用层用例)。

只依赖 ports 接口与 domain 类型,**不知道任何具体实现**。
具体实现由 composition root(fulcrum.app)按配置注入。
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .domain import (
    AuditEvent,
    AuditEventType,
    Context,
    Disposition,
    ExecResult,
    ModelRequest,
    ModelResponse,
    PolicyDecision,
    ToolIntent,
)

if TYPE_CHECKING:  # 仅类型注解,避免运行时耦合
    from .ports import (
        Attributor,
        AuditSink,
        ChainAnalyzer,
        Detector,
        Executor,
        ModelClient,
        PolicyEngine,
        RiskScorer,
        SourceLabeler,
        Tool,
    )


@dataclass(slots=True)
class ToolOutcome:
    intent: ToolIntent
    decision: PolicyDecision
    executed: bool = False
    result: object | None = None


@dataclass(slots=True)
class PipelineResult:
    session_id: str
    response: ModelResponse | None = None
    outcomes: list[ToolOutcome] = field(default_factory=list)


class SecurityPipeline:
    """串联各能力的安全管线。M0 用桩实现端到端跑通。"""

    def __init__(
        self,
        *,
        labeler: SourceLabeler,
        detectors: list[Detector],
        attributor: Attributor,
        risk_scorer: RiskScorer,
        chain_analyzer: ChainAnalyzer,
        policy: PolicyEngine,
        executor: Executor,
        tools: dict[str, Tool],
        audit: AuditSink,
        model_client: ModelClient,
    ) -> None:
        self._labeler = labeler
        self._detectors = detectors
        self._attributor = attributor
        self._risk_scorer = risk_scorer
        self._chain_analyzer = chain_analyzer
        self._policy = policy
        self._executor = executor
        self._tools = tools
        self._audit = audit
        self._model = model_client

    @property
    def audit(self) -> AuditSink:
        """只读访问审计 sink(供审计查询端点使用)。"""
        return self._audit

    # ---- 流程 1:模型请求(/v1/chat/completions)----
    async def handle_model_request(self, req: ModelRequest) -> PipelineResult:
        ctx = Context(session_id=req.session_id, request_id=req.request_id)
        self._emit(ctx, AuditEventType.REQUEST_RECEIVED, subject_id=req.request_id)

        ctx.spans = self._labeler.label(req)
        self._emit(ctx, AuditEventType.SOURCE_LABELED, evidence={"span_count": len(ctx.spans)})

        for detector in self._detectors:
            ctx.findings.extend(detector.detect(ctx.spans, ctx))
        self._emit(
            ctx,
            AuditEventType.INPUT_DETECTED,
            evidence={"findings": [f.model_dump() for f in ctx.findings]},
        )

        resp = await self._model.chat(req)
        self._emit(ctx, AuditEventType.MODEL_FORWARDED, subject_id=resp.response_id)

        result = PipelineResult(session_id=req.session_id, response=resp)
        for call in resp.tool_calls:
            intent = ToolIntent(
                session_id=req.session_id,
                tool_name=call.tool_name,
                arguments=call.arguments,
            )
            result.outcomes.append(self._process_intent(intent, ctx))
        return result

    # ---- 流程 2:直接工具调用(/tools/call)----
    def handle_tool_call(
        self,
        *,
        session_id: str,
        tool_name: str,
        arguments: dict,
        source_ids: list[str] | None = None,
    ) -> ToolOutcome:
        ctx = Context(session_id=session_id)
        intent = ToolIntent(
            session_id=session_id,
            tool_name=tool_name,
            arguments=arguments,
            derived_from_sources=source_ids or [],
        )
        return self._process_intent(intent, ctx)

    # ---- 共用:对单个工具意图做 归因 -> 评分 -> 策略 -> 处置 -> 审计 ----
    def _process_intent(self, intent: ToolIntent, ctx: Context) -> ToolOutcome:
        attribution = self._attributor.attribute(intent, ctx.spans, ctx)
        intent.derived_from_sources = (
            attribution.derived_from_sources or intent.derived_from_sources
        )
        intent.attribution_confidence = attribution.confidence
        intent.risk_score = self._risk_scorer.score(intent, ctx)
        ctx.session_trace.append(intent)
        ctx.findings.extend(self._chain_analyzer.analyze(ctx.session_trace, ctx))
        self._emit(ctx, AuditEventType.TOOL_INTENT_DETECTED, subject_id=intent.intent_id)

        decision = self._policy.decide(intent, ctx)
        self._emit(
            ctx,
            AuditEventType.POLICY_DECIDED,
            subject_id=intent.intent_id,
            decision=decision.decision,
            evidence={"reason": decision.reason, "risk_level": decision.risk_level},
        )

        outcome = ToolOutcome(intent=intent, decision=decision)
        if decision.decision == Disposition.ALLOW:
            tool = self._tools.get(intent.tool_name)
            if tool is None:
                # fail-closed:策略放行了,但工具未知 —— 显式阻断 + 审计,绝不静默跳过。
                outcome.result = ExecResult(ok=False, error=f"unknown tool: {intent.tool_name}")
                self._emit(
                    ctx,
                    AuditEventType.TOOL_BLOCKED,
                    subject_id=intent.intent_id,
                    evidence={"reason": "unknown_tool", "tool": intent.tool_name},
                )
            else:
                outcome.result = self._executor.execute(tool, intent, ctx)
                outcome.executed = True
                self._emit(ctx, AuditEventType.TOOL_EXECUTED, subject_id=intent.intent_id)
        elif decision.decision == Disposition.SANITIZE:
            # M0 未实现真实净化:记录桩并按 fail-closed 暂不执行(等同 pending)。
            self._emit(
                ctx,
                AuditEventType.TOOL_PENDING_APPROVAL,
                subject_id=intent.intent_id,
                evidence={"reason": "sanitize_stub"},
            )
        elif decision.decision == Disposition.APPROVE:
            self._emit(ctx, AuditEventType.TOOL_PENDING_APPROVAL, subject_id=intent.intent_id)
        elif decision.decision == Disposition.BLOCK:
            self._emit(ctx, AuditEventType.TOOL_BLOCKED, subject_id=intent.intent_id)
        return outcome

    # ---- 审计 helper ----
    def _emit(
        self,
        ctx: Context,
        event_type: AuditEventType,
        *,
        subject_id: str | None = None,
        decision: Disposition | None = None,
        evidence: dict | None = None,
    ) -> None:
        event = AuditEvent(
            session_id=ctx.session_id,
            event_type=event_type,
            subject_id=subject_id,
            decision=decision,
            evidence=evidence or {},
        )
        self._audit.append(event)

    @staticmethod
    def _new_id() -> str:
        return uuid.uuid4().hex
