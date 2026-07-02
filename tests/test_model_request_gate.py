"""/v1 模型请求路径的输入闸门(回归 M2/M3)。

M2:handle_model_request 此前对 detect_inputs 的结论**只算不拦**,高危注入照样喂模型。
M3:多来源分片规避(gateway._effective_score)因唯一多 span 入口(本路径)不过闸而是死逻辑。

现改为"仅转发 ALLOW 档":凡 screen 判 BLOCK/APPROVE(含分片聚合升档)一律短路不请求模型。
用固定输出的假检测器 + 记录调用的假模型,直接验证闸门行为(不依赖 keyword_rules 具体分值)。
"""

from __future__ import annotations

import asyncio

from fulcrum.adapters.audit.memory_sink import InMemoryAuditSink
from fulcrum.capabilities import load_builtin_capabilities
from fulcrum.capabilities.policy.allow_all import AllowAllPolicy
from fulcrum.core.domain import Finding, Message, ModelRequest, ModelResponse
from fulcrum.core.pipeline import SecurityPipeline
from fulcrum.core.registry import registry


class _SpyModel:
    """记录是否被请求;被叫到就返回真实回复(闸门放行才该出现)。"""

    def __init__(self) -> None:
        self.calls = 0

    async def chat(self, req: ModelRequest) -> ModelResponse:
        self.calls += 1
        return ModelResponse(request_id=req.request_id, content="模型真实回复")


class _FixedDetector:
    """忽略输入、返回预置 findings —— 把闸门行为与检测器具体分值解耦。"""

    name = "fixed"

    def __init__(self, findings: list[Finding]) -> None:
        self._findings = findings

    def detect(self, spans, ctx) -> list[Finding]:  # noqa: ANN001
        return list(self._findings)


def _pipeline(findings: list[Finding], model: _SpyModel) -> SecurityPipeline:
    load_builtin_capabilities()
    return SecurityPipeline(
        labeler=registry.create("labeler", "passthrough"),
        detectors=[_FixedDetector(findings)],
        attributor=registry.create("attributor", "evidence"),
        risk_scorer=registry.create("risk_scorer", "heuristic"),
        chain_analyzer=registry.create("chain_analyzer", "noop"),
        policy=AllowAllPolicy(),
        executor=registry.create("executor", "echo"),
        tools={},
        audit=InMemoryAuditSink(),
        model_client=model,  # type: ignore[arg-type]
    )


def _run(findings: list[Finding]) -> tuple[str, _SpyModel]:
    model = _SpyModel()
    pipe = _pipeline(findings, model)
    req = ModelRequest(session_id="m", messages=[Message(role="user", content="hi")])
    result = asyncio.run(pipe.handle_model_request(req))
    return (result.response.content if result.response else ""), model


def test_benign_forwards_to_model() -> None:
    # 无风险 finding → ALLOW → 正常请求模型。
    content, model = _run([])
    assert model.calls == 1
    assert content == "模型真实回复"


def test_critical_input_blocked_model_not_called() -> None:
    # 回归 M2:critical(BLOCK)→ 短路,绝不请求模型。
    content, model = _run([Finding(kind="injection", score=0.9, evidence={"source_id": "s1"})])
    assert model.calls == 0
    assert "已拦截" in content


def test_split_payload_across_sources_holds_not_forwarded() -> None:
    # 回归 M3:三个不同来源各夹带中风险(各 0.5 < 复核阈),聚合升至 APPROVE → 挂起,不转发模型。
    findings = [
        Finding(kind="injection", score=0.5, evidence={"source_id": "doc-1"}),
        Finding(kind="exfiltration", score=0.5, evidence={"source_id": "web-2"}),
        Finding(kind="data_poisoning", score=0.5, evidence={"source_id": "mem-3"}),
    ]
    content, model = _run(findings)
    assert model.calls == 0  # 分片聚合升档后不再无条件转发(此前是死逻辑)
    assert "人工复核" in content


def test_two_sources_below_threshold_still_forwarded() -> None:
    # 仅两个来源未达分片阈值(需 ≥3)→ 维持放行,不误伤。
    findings = [
        Finding(kind="injection", score=0.5, evidence={"source_id": "doc-1"}),
        Finding(kind="exfiltration", score=0.5, evidence={"source_id": "web-2"}),
    ]
    _, model = _run(findings)
    assert model.calls == 1
