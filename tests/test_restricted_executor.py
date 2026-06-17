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


class _BigTool:
    name = "big"
    base_risk = 0.1
    model_schema = None

    def call(self, arguments: dict, ctx: Context) -> ExecResult:
        return ExecResult(ok=True, output="A" * 5000)


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


def test_oversized_output_truncated() -> None:
    r = _run(_BigTool(), {"path": "notice.txt"}, max_output_chars=100)
    assert r.ok  # 仍算成功,但输出被截断
    assert len(r.output or "") < 5000
    assert "截断" in (r.output or "")
    assert r.side_effects.get("sandbox") == "output_truncated"


def test_output_under_cap_untouched() -> None:
    r = _run(_PassTool(), {"path": "notice.txt"}, max_output_chars=100)
    assert r.ok and r.output == "done"  # 未超限,原样返回
    assert "sandbox" not in r.side_effects


class _RecordingTool:
    """记录是否被真正调用,用于验证超体积载荷在执行前即被拒(未触达工具)。"""

    name = "rec"
    base_risk = 0.1
    model_schema = None

    def __init__(self) -> None:
        self.called = False

    def call(self, arguments: dict, ctx: Context) -> ExecResult:
        self.called = True
        return ExecResult(ok=True, output="done")


def test_oversized_input_payload_denied_before_exec() -> None:
    tool = _RecordingTool()
    # 目标域名在白名单内(外联放行),但参数体超上限 → 仍按批量外泄拒绝,且不触达工具。
    r = _run(
        tool,
        {"url": "https://gov.cn/x", "body": "A" * 5000},
        allow_domains=["gov.cn"],
        max_input_chars=100,
    )
    assert not r.ok and "批量外泄" in (r.error or "")
    assert r.side_effects.get("sandbox") == "denied"
    assert tool.called is False  # 执行前边界:工具未被调用


def test_input_under_cap_passes() -> None:
    r = _run(_PassTool(), {"path": "notice.txt", "body": "A" * 50}, max_input_chars=100)
    assert r.ok and r.output == "done"


def test_input_payload_counts_nested_and_keys() -> None:
    # 数据塞进嵌套列表/键名同样计入体积,堵"换个容器就绕过"。
    big = {"a" * 60: ["B" * 60, {"c": "D" * 60}]}
    r = _run(_PassTool(), big, max_input_chars=100)
    assert not r.ok and "批量外泄" in (r.error or "")


def test_default_input_cap_is_generous() -> None:
    # 默认 64KB:寻常办公参数不应被误拒(不传 max_input_chars)。
    r = _run(_PassTool(), {"path": "notice.txt", "text": "正常公文内容" * 200})
    assert r.ok and r.output == "done"
