"""受控文件工具 file.read / file.write:工作区边界 + 写入体积上限(纵深防御)。"""

from __future__ import annotations

import pytest

from fulcrum.capabilities.tools import file_tools
from fulcrum.capabilities.tools.file_tools import _MAX_WRITE, FileReadTool, FileWriteTool
from fulcrum.core.domain import Context

_CTX = Context(session_id="s")


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    """把受控工作区指到临时目录,避免污染仓库内 data/workspace。"""
    monkeypatch.setattr(file_tools, "_WORKSPACE", tmp_path)
    return tmp_path


def test_write_then_read_roundtrip(workspace) -> None:
    target = workspace / "note.txt"
    wrote = FileWriteTool().call({"path": str(target), "content": "你好"}, _CTX)
    assert wrote.ok
    read = FileReadTool().call({"path": str(target)}, _CTX)
    assert read.ok and read.output == "你好"


def test_oversized_write_denied_before_touching_disk(workspace) -> None:
    """超限内容在落盘前即被拒,文件不应被创建(防批量落盘外泄 / 磁盘耗尽)。"""
    target = workspace / "big.txt"
    res = FileWriteTool().call({"path": str(target), "content": "x" * (_MAX_WRITE + 1)}, _CTX)
    assert res.ok is False
    assert "上限" in (res.error or "")
    assert not target.exists()


def test_write_at_cap_boundary_allowed(workspace) -> None:
    """恰好等于上限放行(边界用 == 而非 >)。"""
    target = workspace / "edge.txt"
    res = FileWriteTool().call({"path": str(target), "content": "x" * _MAX_WRITE}, _CTX)
    assert res.ok
    assert target.exists()


def test_write_outside_workspace_denied(workspace) -> None:
    res = FileWriteTool().call({"path": "/etc/evil.txt", "content": "x"}, _CTX)
    assert res.ok is False
    assert "越出受控工作区" in (res.error or "")
