"""安全管线编排(应用层用例)。

只依赖 ports 接口与 domain 类型,**不知道任何具体实现**。
具体实现由 composition root(fulcrum.app)按配置注入。
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .domain import (
    AuditEvent,
    AuditEventType,
    Context,
    Disposition,
    ExecResult,
    Finding,
    Message,
    ModelRequest,
    ModelResponse,
    PolicyDecision,
    RiskLevel,
    ToolIntent,
)
from .gateway import GateVerdict, screen

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

        self._run_detectors(ctx)
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
            result.outcomes.append(await self._process_intent(intent, ctx))
        return result

    # ---- 流程 1b:前置输入闸门(/gateway/chat 用)----
    def screen_input(self, session_id: str, message: str) -> GateVerdict:
        """对一条用户输入做"标注 → 检测 → 闸门",产出拦截/审核/放行结论并落审计。

        只用检测器既有结论(judgment 不变),闸门映射见 core.gateway.screen。
        网关据此决定是否把请求转发给企业智能体。

        威胁模型:互联网前门的访客一律视为**不可信来源**(UNTRUSTED)——这是给检测器
        喂的"信任标注",不是检测算法本身;passthrough/keyword_rules 均零改动。
        (内部沙盘把窗口人员标 TRUSTED 是另一套场景,二者并存、互不影响。)
        """
        from .domain import SourceSpan, SourceType, TrustLevel

        req = ModelRequest(session_id=session_id, messages=[Message(role="user", content=message)])
        ctx = Context(session_id=session_id, request_id=req.request_id)
        self._emit(ctx, AuditEventType.REQUEST_RECEIVED, subject_id=req.request_id)

        ctx.spans = [
            SourceSpan(
                source_type=SourceType.USER,
                trust_level=TrustLevel.UNTRUSTED,
                content_hash=hashlib.sha256(message.encode("utf-8")).hexdigest(),
                excerpt=message[:600],
            )
        ]
        self._emit(ctx, AuditEventType.SOURCE_LABELED, evidence={"span_count": len(ctx.spans)})

        self._run_detectors(ctx)
        self._emit(
            ctx,
            AuditEventType.INPUT_DETECTED,
            evidence={"findings": [f.model_dump() for f in ctx.findings]},
        )

        verdict = screen(ctx.findings)
        self._emit(
            ctx,
            AuditEventType.POLICY_DECIDED,
            subject_id=req.request_id,
            decision=verdict.decision,
            evidence={"reason": verdict.reason, "risk_level": verdict.risk_level},
        )
        if verdict.decision == Disposition.BLOCK:
            self._emit(ctx, AuditEventType.TOOL_BLOCKED, subject_id=req.request_id)
        elif verdict.decision == Disposition.APPROVE:
            self._emit(ctx, AuditEventType.TOOL_PENDING_APPROVAL, subject_id=req.request_id)
        else:
            self._emit(ctx, AuditEventType.MODEL_FORWARDED, subject_id=req.request_id)
        return verdict

    # ---- 流程 2:直接工具调用(/tools/call)----
    async def handle_tool_call(
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
        return await self._process_intent(intent, ctx)

    # ---- 共用:对单个工具意图做 归因 -> 评分 -> 策略 -> 处置 -> 审计 ----
    async def _process_intent(self, intent: ToolIntent, ctx: Context) -> ToolOutcome:
        # 安全关键评估段(归因/评分/链分析/策略):任一阶段抛错 → fail-closed 阻断 + 留痕。
        # 编排层亲自拥有 fail-closed,不把"插件实现永不抛异常"这个不成立的信任下放出去。
        try:
            attribution = await self._attributor.attribute(intent, ctx.spans, ctx)
            intent.derived_from_sources = (
                attribution.derived_from_sources or intent.derived_from_sources
            )
            intent.attribution_confidence = attribution.confidence
            intent.risk_score = self._risk_scorer.score(intent, ctx)
            ctx.request_trace.append(intent)
            ctx.findings.extend(await self._chain_analyzer.analyze(ctx.request_trace, ctx))
            self._emit(ctx, AuditEventType.TOOL_INTENT_DETECTED, subject_id=intent.intent_id)
            decision = await self._policy.decide(intent, ctx)
        except Exception as exc:  # noqa: BLE001 —— 安全边界:任何异常都必须 fail-closed
            return self._fail_closed(ctx, intent, "risk_assessment", exc)

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
                try:
                    outcome.result = await self._executor.execute(tool, intent, ctx)
                    outcome.executed = True
                    self._emit(ctx, AuditEventType.TOOL_EXECUTED, subject_id=intent.intent_id)
                except Exception as exc:  # noqa: BLE001 —— 执行抛错不得 fail-open
                    # 动作已被策略允许,但执行崩溃 → 记错误结果 + 留痕,绝不静默 500。
                    outcome.result = ExecResult(ok=False, error=f"executor error: {exc}")
                    self._emit(
                        ctx,
                        AuditEventType.TOOL_BLOCKED,
                        subject_id=intent.intent_id,
                        evidence={"reason": "executor_error", "error": str(exc)},
                    )
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

    # ---- fail-closed:安全关键阶段抛错时的统一降级处置 ----
    def _fail_closed(
        self, ctx: Context, intent: ToolIntent, stage: str, exc: Exception
    ) -> ToolOutcome:
        """风险评估/策略阶段抛错 → 合成 BLOCK 处置 + 双重留痕,绝不让请求 fail-open。

        安全关键路径失败时默认拒绝(arch 铁律);异常细节进审计,不外泄给调用方。
        """
        decision = PolicyDecision(
            decision=Disposition.BLOCK,
            reason=f"{stage} 阶段异常,按 fail-closed 阻断",
            matched_policy_id="fail-closed",
            risk_level=RiskLevel.CRITICAL,
        )
        self._emit(
            ctx,
            AuditEventType.POLICY_DECIDED,
            subject_id=intent.intent_id,
            decision=decision.decision,
            evidence={"reason": decision.reason, "stage": stage, "error": str(exc)},
        )
        self._emit(
            ctx,
            AuditEventType.TOOL_BLOCKED,
            subject_id=intent.intent_id,
            evidence={"reason": "fail_closed", "stage": stage},
        )
        return ToolOutcome(intent=intent, decision=decision)

    # ---- 检测:逐个检测器 fail-closed(某检测器崩溃 → 合成高危 Finding,绝不静默放行)----
    def _run_detectors(self, ctx: Context) -> None:
        for detector in self._detectors:
            try:
                ctx.findings.extend(detector.detect(ctx.spans, ctx))
            except Exception as exc:  # noqa: BLE001 —— 检测器崩溃当作高危信号,不得 fail-open
                name = getattr(detector, "name", detector.__class__.__name__)
                ctx.findings.append(
                    Finding(
                        kind="detector_error",
                        score=1.0,  # critical:让 screen()/策略按高危拦截
                        evidence={"detector": name, "error": str(exc)},
                    )
                )
                self._emit(
                    ctx,
                    AuditEventType.INPUT_DETECTED,
                    evidence={"reason": "detector_error", "detector": name, "error": str(exc)},
                )

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
