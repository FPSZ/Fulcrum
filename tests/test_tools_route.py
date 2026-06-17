"""工具网关流水:工具调用穿过枢衡的治理记录(真管线 + 纯映射)。

验证工具网关页接真的后端契约:每次工具调用过 归因→评分→策略→处置,判定点落带丰富证据的
审计,据此投影成工具调用流水(工具/参数/风险/归因/来源信任/命中规则/是否执行)。
"""

from __future__ import annotations

import asyncio

from fulcrum.adapters.api.tools_routes import build_tool_calls
from fulcrum.adapters.audit.memory_sink import InMemoryAuditSink
from fulcrum.app import build_pipeline
from fulcrum.core.domain import AuditEvent, AuditEventType, Disposition
from fulcrum.eval.__main__ import _EVAL_CONFIG


def test_real_tool_calls_governed_and_projected() -> None:
    pipe = build_pipeline(_EVAL_CONFIG)  # 真治理管线(政务 yaml 策略 + echo 工具)
    # 一条高危命令(被策略阻断)+ 一条良性 echo(放行并执行)
    asyncio.run(
        pipe.handle_tool_call(
            session_id="s", tool_name="shell.exec", arguments={"command": "rm -rf /data"}
        )
    )
    asyncio.run(
        pipe.handle_tool_call(session_id="s", tool_name="echo", arguments={"text": "hello"})
    )

    sink = pipe.audit
    assert isinstance(sink, InMemoryAuditSink)
    calls = build_tool_calls(sink.all_events())
    by_tool = {c.tool: c for c in calls}

    assert "shell.exec" in by_tool and "echo" in by_tool

    shell = by_tool["shell.exec"]
    assert shell.decision == Disposition.BLOCK.value
    assert shell.rule  # 命中了某条策略规则
    assert shell.reason
    assert shell.risk_score > 0
    assert "rm -rf" in shell.args
    assert shell.executed is False  # 阻断未执行

    echo = by_tool["echo"]
    assert echo.decision == Disposition.ALLOW.value
    assert echo.executed is True  # 放行并执行 → 有 tool_executed 关联

    # 按时间倒序
    assert [c.time for c in calls] == sorted((c.time for c in calls), reverse=True)


def test_build_tool_calls_filters_and_correlates() -> None:
    """只取带 tool 证据的判定点(排除输入闸门判定);executed 由 tool_executed 关联。"""
    events = [
        # 输入闸门判定点(无 tool)→ 不算工具调用
        AuditEvent(
            session_id="s",
            event_type=AuditEventType.POLICY_DECIDED,
            decision=Disposition.BLOCK,
            evidence={"reason": "恶意输入", "stage": "input_gateway"},
        ),
        # 工具判定点(放行)
        AuditEvent(
            session_id="s",
            event_type=AuditEventType.POLICY_DECIDED,
            subject_id="intent-1",
            decision=Disposition.ALLOW,
            evidence={"tool": "echo", "args": '{"text":"hi"}', "risk_score": 0.2},
        ),
        AuditEvent(
            session_id="s",
            event_type=AuditEventType.TOOL_EXECUTED,
            subject_id="intent-1",
        ),
    ]
    calls = build_tool_calls(events)
    assert len(calls) == 1  # 输入闸门那条被排除
    assert calls[0].tool == "echo"
    assert calls[0].executed is True  # 关联到 intent-1 的 tool_executed
