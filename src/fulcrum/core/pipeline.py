"""安全管线编排(应用层用例)。

只依赖 ports 接口与 domain 类型,**不知道任何具体实现**。
具体实现由 composition root(fulcrum.app)按配置注入。
"""

from __future__ import annotations

import hashlib
import json
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
    SourceSpan,
    SourceType,
    ToolIntent,
    TrustLevel,
)
from .gateway import GateVerdict, screen, screen_output
from .redaction import redact

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


def _short_args(args: dict) -> str:
    """工具参数的可展示摘要(截断,避免审计/展示里塞入超长或敏感全文)。"""
    try:
        text = json.dumps(args, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        text = str(args)
    return text[:200]


def _intent_source_trust(intent: ToolIntent, ctx: Context) -> str | None:
    """本次调用所依据来源的最坏信任级(worst-first);无可核验来源则 None。

    与策略引擎判信任同口径:取 intent 归因到的各来源 span 里最不可信的一档;有声明来源
    却无 span 可核验(工具网关路径)→ 视为不可信(fail-closed)。
    """
    by_id = {s.source_id: s for s in ctx.spans}
    trusts = {by_id[sid].trust_level for sid in intent.derived_from_sources if sid in by_id}
    for level in (TrustLevel.UNTRUSTED, TrustLevel.SEMI_TRUSTED, TrustLevel.TRUSTED):
        if level in trusts:
            return level.value
    if intent.derived_from_sources:
        return TrustLevel.UNTRUSTED.value
    return None


@dataclass(slots=True)
class ToolOutcome:
    intent: ToolIntent
    decision: PolicyDecision
    executed: bool = False
    result: ExecResult | None = None  # 执行/降级结果;未执行(审批/阻断)时为 None


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

    @property
    def policy(self) -> PolicyEngine:
        """只读访问策略引擎(供策略中心展示「当前装配的策略」)。"""
        return self._policy

    def model_tool_schemas(self) -> list[dict]:
        """装配工具里声明了 model_schema 的 OpenAI function 规格列表。

        供 agent 适配器据此**只**向模型暴露管线实际管控的工具——单一真源,加工具自动同步,
        不再各处手抄一份工具声明。无 model_schema 的工具(如内部 echo)不对模型暴露。
        """
        out: list[dict] = []
        for tool in self._tools.values():
            schema = getattr(tool, "model_schema", None)
            if schema is not None:
                out.append(schema)
        return out

    # ---- 流程 1:模型请求(/v1/chat/completions)----
    async def handle_model_request(self, req: ModelRequest) -> PipelineResult:
        ctx = Context(session_id=req.session_id, request_id=req.request_id)
        await self._emit(ctx, AuditEventType.REQUEST_RECEIVED, subject_id=req.request_id)

        ctx.spans = self._labeler.label(req)
        await self._emit(
            ctx, AuditEventType.SOURCE_LABELED, evidence={"span_count": len(ctx.spans)}
        )

        await self.detect_inputs(ctx, ctx.spans)

        resp = await self._model.chat(req)
        await self._emit(ctx, AuditEventType.MODEL_FORWARDED, subject_id=resp.response_id)

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
    async def screen_input(self, session_id: str, message: str) -> GateVerdict:
        """对一条用户输入做"标注 → 检测 → 闸门",产出拦截/审核/放行结论并落审计。

        只用检测器既有结论(judgment 不变),闸门映射见 core.gateway.screen。
        网关据此决定是否把请求转发给企业智能体。

        威胁模型:互联网前门的访客一律视为**不可信来源**(UNTRUSTED)——这是给检测器
        喂的"信任标注",不是检测算法本身;passthrough/keyword_rules 均零改动。
        (内部沙盘把窗口人员标 TRUSTED 是另一套场景,二者并存、互不影响。)
        """
        req = ModelRequest(session_id=session_id, messages=[Message(role="user", content=message)])
        ctx = Context(session_id=session_id, request_id=req.request_id)
        await self._emit(ctx, AuditEventType.REQUEST_RECEIVED, subject_id=req.request_id)

        ctx.spans = [
            SourceSpan(
                source_type=SourceType.USER,
                trust_level=TrustLevel.UNTRUSTED,
                content_hash=hashlib.sha256(message.encode("utf-8")).hexdigest(),
                excerpt=message[:600],
            )
        ]
        await self._emit(
            ctx, AuditEventType.SOURCE_LABELED, evidence={"span_count": len(ctx.spans)}
        )

        await self.detect_inputs(ctx, ctx.spans)

        verdict = screen(ctx.findings)
        # 富化判定证据:把"这条输入凭什么这么判"的可展示依据落进审计 —— 供事件页逐事件
        # 溯源(摘要/来源/置信度)。这些是观测字段,随事件入哈希(只影响新事件自身)。
        await self._emit(
            ctx,
            AuditEventType.POLICY_DECIDED,
            subject_id=req.request_id,
            decision=verdict.decision,
            evidence={
                "reason": verdict.reason,
                "risk_level": verdict.risk_level,
                "max_score": verdict.max_score,
                "top_kind": verdict.top_kind,
                # 审计摘要脱敏:身份证/手机/密钥等不以明文落库(检测仍看全文,见 ctx.spans)。
                "excerpt": redact(message[:200]),
                "source_type": SourceType.USER.value,
                "trust_level": TrustLevel.UNTRUSTED.value,
                "stage": "input_gateway",
            },
        )
        if verdict.decision == Disposition.BLOCK:
            await self._emit(ctx, AuditEventType.TOOL_BLOCKED, subject_id=req.request_id)
        elif verdict.decision == Disposition.APPROVE:
            await self._emit(ctx, AuditEventType.TOOL_PENDING_APPROVAL, subject_id=req.request_id)
        else:
            await self._emit(ctx, AuditEventType.MODEL_FORWARDED, subject_id=req.request_id)
        return verdict

    # ---- 流程 1c:出口闸门(/gateway/chat 收到企业智能体回复后)----
    async def screen_output(self, session_id: str, text: str) -> GateVerdict:
        """对**企业智能体的回复**做"检测 → 出口闸门",判敏感/危险内容并落审计。

        对应安全问题路径「响应后检查模型输出」(01 §4.2):入口拦恶意输入,出口拦回复里的
        敏感数据外泄 / 危险内容,两道对称。出口对回复按**不可信内容全权检测**——泄露就是泄露,
        不因"是自家 agent 说的"就放松(agent 可能已被污染上下文带偏);闸门语义见
        core.gateway.screen_output。
        """
        ctx = Context(session_id=session_id)
        ctx.spans = [
            SourceSpan(
                source_type=SourceType.ASSISTANT,
                trust_level=TrustLevel.UNTRUSTED,
                content_hash=hashlib.sha256(text.encode("utf-8")).hexdigest(),
                excerpt=text[:600],
            )
        ]
        await self.detect_inputs(ctx, ctx.spans)

        verdict = screen_output(ctx.findings)
        await self._emit(
            ctx,
            AuditEventType.POLICY_DECIDED,
            decision=verdict.decision,
            evidence={
                "reason": verdict.reason,
                "risk_level": verdict.risk_level,
                "max_score": verdict.max_score,
                "top_kind": verdict.top_kind,
                "excerpt": text[:200],
                "source_type": SourceType.ASSISTANT.value,
                "trust_level": TrustLevel.UNTRUSTED.value,
                "stage": "output_gateway",
            },
        )
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

    # ---- 供 agent 循环适配器复用:对单个意图做完整评估(调用方持有并复用 ctx)----
    async def evaluate_intent(self, intent: ToolIntent, ctx: Context) -> ToolOutcome:
        """完整安全评估与处置(归因→评分→链→策略→fail-closed→执行→审计)。

        与 handle_tool_call 的区别:**调用方提供并复用 ctx**,使多轮 agent 循环里跨轮累积的
        spans / request_trace 能被归因与链分析看见。demo 与真实网关都经此单一真源——
        fail-closed 等内核保证对它们一视同仁,适配器不再各自手撸评估链。
        """
        return await self._process_intent(intent, ctx)

    # ---- 共用:对单个工具意图做 归因 -> 评分 -> 策略 -> 处置 -> 审计 ----
    async def _process_intent(self, intent: ToolIntent, ctx: Context) -> ToolOutcome:
        # 工具一处查定,贯穿评分(盖戳基础风险)与执行(ALLOW 分支),不重复查表。
        tool = self._tools.get(intent.tool_name)
        # 安全关键评估段(归因/评分/链分析/策略):任一阶段抛错 → fail-closed 阻断 + 留痕。
        # 编排层亲自拥有 fail-closed,不把"插件实现永不抛异常"这个不成立的信任下放出去。
        try:
            attribution = await self._attributor.attribute(intent, ctx.spans, ctx)
            intent.derived_from_sources = (
                attribution.derived_from_sources or intent.derived_from_sources
            )
            intent.attribution_confidence = attribution.confidence
            intent.attribution_rationale = attribution.rationale
            # 评分前盖戳工具固有基础风险(工具未注册 → 留 None,评分器用兜底);
            # 由此评分器无需枚举工具名,加工具零改评分器。
            if tool is not None:
                intent.base_risk = getattr(tool, "base_risk", None)
            intent.risk_score = self._risk_scorer.score(intent, ctx)
            ctx.request_trace.append(intent)
            ctx.findings.extend(await self._chain_analyzer.analyze(ctx.request_trace, ctx))
            await self._emit(ctx, AuditEventType.TOOL_INTENT_DETECTED, subject_id=intent.intent_id)
            decision = await self._policy.decide(intent, ctx)
        except Exception as exc:  # noqa: BLE001 —— 安全边界:任何异常都必须 fail-closed
            return await self._fail_closed(ctx, intent, "risk_assessment", exc)

        # 富化工具治理证据:把"这次工具调用凭什么这么判"的可展示依据落进审计 ——
        # 供工具网关页逐调用展示(工具/参数/风险/归因/来源信任/命中规则)。这些字段都来自
        # 本次 intent / decision,随判定点事件入哈希(只影响新事件自身)。
        await self._emit(
            ctx,
            AuditEventType.POLICY_DECIDED,
            subject_id=intent.intent_id,
            decision=decision.decision,
            evidence={
                "reason": decision.reason,
                "risk_level": decision.risk_level,
                "tool": intent.tool_name,
                "args": _short_args(intent.arguments),
                "risk_score": intent.risk_score,
                "attribution_confidence": intent.attribution_confidence,
                "source_trust": _intent_source_trust(intent, ctx),
                "matched_policy": decision.matched_policy_id,
            },
        )

        outcome = ToolOutcome(intent=intent, decision=decision)
        if decision.decision == Disposition.ALLOW:
            if tool is None:
                # fail-closed:策略放行了,但工具未知 —— 显式阻断 + 审计,绝不静默跳过。
                outcome.result = ExecResult(ok=False, error=f"unknown tool: {intent.tool_name}")
                await self._emit(
                    ctx,
                    AuditEventType.TOOL_BLOCKED,
                    subject_id=intent.intent_id,
                    evidence={"reason": "unknown_tool", "tool": intent.tool_name},
                )
            else:
                try:
                    outcome.result = await self._executor.execute(tool, intent, ctx)
                    outcome.executed = True
                    # 记录工具返回(截断)→ 供后续步骤的跨步污点链分析比对来源。
                    if outcome.result.output:
                        ctx.tool_returns.append(outcome.result.output[:500])
                    await self._emit(ctx, AuditEventType.TOOL_EXECUTED, subject_id=intent.intent_id)
                except Exception as exc:  # noqa: BLE001 —— 执行抛错不得 fail-open
                    # 动作已被策略允许,但执行崩溃 → 记错误结果 + 留痕,绝不静默 500。
                    outcome.result = ExecResult(ok=False, error=f"executor error: {exc}")
                    await self._emit(
                        ctx,
                        AuditEventType.TOOL_BLOCKED,
                        subject_id=intent.intent_id,
                        evidence={"reason": "executor_error", "error": str(exc)},
                    )
        elif decision.decision == Disposition.SANITIZE:
            # M0 未实现真实净化:记录桩并按 fail-closed 暂不执行(等同 pending)。
            await self._emit(
                ctx,
                AuditEventType.TOOL_PENDING_APPROVAL,
                subject_id=intent.intent_id,
                evidence={"reason": "sanitize_stub"},
            )
        elif decision.decision == Disposition.APPROVE:
            await self._emit(ctx, AuditEventType.TOOL_PENDING_APPROVAL, subject_id=intent.intent_id)
        elif decision.decision == Disposition.BLOCK:
            await self._emit(ctx, AuditEventType.TOOL_BLOCKED, subject_id=intent.intent_id)
        return outcome

    # ---- fail-closed:安全关键阶段抛错时的统一降级处置 ----
    async def _fail_closed(
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
        await self._emit(
            ctx,
            AuditEventType.POLICY_DECIDED,
            subject_id=intent.intent_id,
            decision=decision.decision,
            evidence={"reason": decision.reason, "stage": stage, "error": str(exc)},
        )
        await self._emit(
            ctx,
            AuditEventType.TOOL_BLOCKED,
            subject_id=intent.intent_id,
            evidence={"reason": "fail_closed", "stage": stage},
        )
        return ToolOutcome(intent=intent, decision=decision)

    # ---- 输入检测(供 agent 循环复用:用户输入 / 工具返回间接注入 走同一套检测器)----
    async def detect_inputs(self, ctx: Context, spans: list[SourceSpan]) -> list[Finding]:
        """对一批新输入 span 跑全部检测器(逐个 fail-closed),累积进 ctx + 落审计,返回新增。"""
        new = await self._run_detectors(ctx, spans)
        await self._emit(
            ctx,
            AuditEventType.INPUT_DETECTED,
            evidence={"findings": [f.model_dump() for f in new]},
        )
        return new

    # ---- 检测:逐个检测器 fail-closed(某检测器崩溃 → 合成高危 Finding,绝不静默放行)----
    async def _run_detectors(self, ctx: Context, spans: list[SourceSpan]) -> list[Finding]:
        new: list[Finding] = []
        for detector in self._detectors:
            try:
                new.extend(detector.detect(spans, ctx))
            except Exception as exc:  # noqa: BLE001 —— 检测器崩溃当作高危信号,不得 fail-open
                name = getattr(detector, "name", detector.__class__.__name__)
                new.append(
                    Finding(
                        kind="detector_error",
                        score=1.0,  # critical:让 screen()/策略按高危拦截
                        evidence={"detector": name, "error": str(exc)},
                    )
                )
                await self._emit(
                    ctx,
                    AuditEventType.INPUT_DETECTED,
                    evidence={"reason": "detector_error", "detector": name, "error": str(exc)},
                )
        ctx.findings.extend(new)
        return new

    # ---- 审计 helper ----
    async def _emit(
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
        await self._audit.append(event)

    # ---- 供 agent 循环适配器把"循环级"审计事件写入同一条链 ----
    async def record(
        self,
        ctx: Context,
        event_type: AuditEventType,
        *,
        subject_id: str | None = None,
        decision: Disposition | None = None,
        evidence: dict | None = None,
    ) -> None:
        """循环级事件(收到请求 / 已转发模型 等)入审计链。逐意图事件由 evaluate_intent 自己落。"""
        await self._emit(
            ctx, event_type, subject_id=subject_id, decision=decision, evidence=evidence
        )
