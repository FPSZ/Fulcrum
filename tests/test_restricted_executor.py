"""RestrictedExecutor:执行前强制边界(涉密/越界/高危/外联)+ 超时。"""

from __future__ import annotations

import asyncio
import time

from fulcrum.capabilities.sandbox.restricted_executor import RestrictedExecutor
from fulcrum.core.domain import Context, ExecResult, ToolIntent


class _PassTool:
    name = "x"
    base_risk = 0.1
    model_schema = None

    def call(self, arguments: dict, ctx: Context) -> ExecResult:
        return ExecResult(ok=True, output="done")


class _SlowTool:
    name = "slow"
    base_risk = 0.1
    model_schema = None

    def call(self, arguments: dict, ctx: Context) -> ExecResult:
        time.sleep(0.5)
        return ExecResult(ok=True, output="late")


def _run(tool: object, args: dict, **kw: object) -> ExecResult:
    ex = RestrictedExecutor(**kw)  # type: ignore[arg-type]
    intent = ToolIntent(session_id="s", tool_name=getattr(tool, "name", "x"), arguments=args)
    return asyncio.run(ex.execute(tool, intent, Context(session_id="s")))  # type: ignore[arg-type]


def test_benign_passthrough() -> None:
    r = _run(_PassTool(), {"path": "notice.txt"})
    assert r.ok and r.output == "done"


def test_sensitive_path_denied() -> None:
    r = _run(_PassTool(), {"path": "/etc/passwd"})
    assert not r.ok
    assert "涉密" in (r.error or "") or "敏感" in (r.error or "")
    assert r.side_effects.get("sandbox") == "denied"


def test_outside_workspace_denied() -> None:
    r = _run(_PassTool(), {"path": "../outside.txt"})
    assert not r.ok and "越出" in (r.error or "")


def test_dangerous_command_denied() -> None:
    r = _run(_PassTool(), {"command": "rm -rf /data"})
    assert not r.ok and "高危" in (r.error or "")


def test_network_off_by_default() -> None:
    r = _run(_PassTool(), {"url": "https://gov.cn/x"})
    assert not r.ok and "外联" in (r.error or "")


def test_network_allowlisted_passes() -> None:
    r = _run(_PassTool(), {"url": "https://gov.cn/x"}, allow_domains=["gov.cn"])
    assert r.ok and r.output == "done"


def test_timeout_enforced() -> None:
    r = _run(_SlowTool(), {"path": "notice.txt"}, timeout_seconds=0.05)
    assert not r.ok and "超时" in (r.error or "")
