"""区域检测配置契约：新分区格式与旧扁平格式都须在构建期严格校验。"""

from __future__ import annotations

import asyncio
import copy

import pytest

from fulcrum.adapters.audit.memory_sink import InMemoryAuditSink
from fulcrum.adapters.model.fake_client import FakeModelClient
from fulcrum.app import build_pipeline
from fulcrum.capabilities import load_builtin_capabilities
from fulcrum.config import DETECTOR_ZONES, load_capability_config, normalize_detector_zones
from fulcrum.core.domain import Context, ToolIntent
from fulcrum.core.errors import ConfigError
from fulcrum.core.pipeline import SecurityPipeline
from fulcrum.core.registry import registry


class _RecordingDetector:
    """不依赖规则内容，直接记录被哪个区域调用的测试替身。"""

    def __init__(self, name: str, calls: list[str]) -> None:
        self.name = name
        self._calls = calls

    def detect(self, _spans: object, _ctx: object) -> list:
        self._calls.append(self.name)
        return []


def _base_config(detectors: object) -> dict:
    return {
        "labeler": "passthrough",
        "detectors": detectors,
        "attributor": "evidence",
        "risk_scorer": "heuristic",
        "chain_analyzer": "noop",
        "policy": "allow_all",
        "executor": "echo",
        "tools": ["echo"],
        "model": "fake",
        "audit": "memory",
    }


def test_flat_detector_list_maps_to_all_zones() -> None:
    zones = normalize_detector_zones(["keyword_rules", "secret_egress"])

    assert tuple(zones) == DETECTOR_ZONES
    assert all(names == ["keyword_rules", "secret_egress"] for names in zones.values())


def test_grouped_config_keeps_independent_detector_sets() -> None:
    config = _base_config(
        {
            "gateway_input": ["keyword_rules"],
            "gateway_output": ["secret_egress"],
            "tool_return": ["keyword_rules", "secret_egress"],
            "assistant_intent": [],
        }
    )
    pipeline = build_pipeline(config)

    assert [detector.name for detector in pipeline.detector_zones["gateway_input"]] == [
        "keyword_rules"
    ]
    assert [detector.name for detector in pipeline.detector_zones["gateway_output"]] == [
        "secret_egress"
    ]
    assert pipeline.detector_zones["assistant_intent"] == ()


@pytest.mark.parametrize(
    ("detectors", "message"),
    [
        ({"gateway_input": []}, "缺少区域"),
        (
            {
                "gateway_input": [],
                "gateway_output": [],
                "tool_return": [],
                "assistant_intent": [],
                "typo_zone": [],
            },
            "未知区域",
        ),
        ({zone: "keyword_rules" for zone in DETECTOR_ZONES}, "必须是检测器名称列表"),
    ],
)
def test_invalid_zone_schema_rejected(detectors: object, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        build_pipeline(_base_config(detectors))


def test_unknown_detector_rejected_during_pipeline_build() -> None:
    config = _base_config({zone: ["does_not_exist"] for zone in DETECTOR_ZONES})

    with pytest.raises(ConfigError, match="未找到能力实现"):
        build_pipeline(config)


def test_default_config_declares_all_detector_zones() -> None:
    config = load_capability_config()

    assert isinstance(config["detectors"], dict)
    assert tuple(config["detector_zones"]) == DETECTOR_ZONES
    # 复制后改动一个区域不应污染其他区域(即使 YAML 用 anchor 表示默认同配)。
    zones = copy.deepcopy(config["detector_zones"])
    zones["gateway_input"].pop()
    assert zones["gateway_input"] != zones["gateway_output"]


def _zoned_pipeline(calls: list[str]) -> SecurityPipeline:
    load_builtin_capabilities()
    zones = {zone: [_RecordingDetector(zone, calls)] for zone in DETECTOR_ZONES}
    return SecurityPipeline(
        labeler=registry.create("labeler", "passthrough"),
        detectors=[detector for detectors in zones.values() for detector in detectors],
        detector_zones=zones,
        attributor=registry.create("attributor", "zero"),
        risk_scorer=registry.create("risk_scorer", "zero"),
        chain_analyzer=registry.create("chain_analyzer", "noop"),
        policy=registry.create("policy", "allow_all"),
        executor=registry.create("executor", "echo"),
        tools={"echo": registry.create("tool", "echo")},
        audit=InMemoryAuditSink(),
        model_client=FakeModelClient(),
    )


def test_each_security_entry_uses_its_detector_zone_and_audits_summary() -> None:
    calls: list[str] = []
    pipeline = _zoned_pipeline(calls)

    asyncio.run(pipeline.screen_input("zones", "正常输入"))
    asyncio.run(pipeline.screen_output("zones", "正常回复"))
    asyncio.run(pipeline.screen_tool_return("zones", "正常工具返回"))
    asyncio.run(
        pipeline.evaluate_intent(
            ToolIntent(session_id="zones", tool_name="echo", arguments={"text": "正常参数"}),
            Context(session_id="zones"),
        )
    )

    assert calls == list(DETECTOR_ZONES)
    events = asyncio.run(pipeline.audit.events("zones"))
    summaries = [event.evidence.get("detector_config") for event in events]
    summaries = [summary for summary in summaries if summary]
    assert {summary["zone"] for summary in summaries} >= set(DETECTOR_ZONES)
    assert all(len(str(summary["revision"])) == 16 for summary in summaries)
    assert all("options" not in summary for summary in summaries)
