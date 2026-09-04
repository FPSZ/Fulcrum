"""RestrictedExecutor:执行前强制边界(涉密/越界/高危/外联)+ 超时。"""

from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path

import pytest

from fulcrum.capabilities.sandbox.restricted_executor import (
    RestrictedExecutor,
    _disallowed_url_scheme,
    _realpath_escapes,
)
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


def test_file_scheme_url_denied_even_with_allowlist() -> None:
    """file:///etc/passwd 无主机 → domain_allowed 返回 True 会绕过外联白名单,须按协议白名单拦下。"""
    tool = _RecordingTool()
    r = _run(tool, {"url": "file:///etc/passwd"}, allow_domains=["gov.cn"])
    assert not r.ok and "协议" in (r.error or "")
    assert r.side_effects.get("sandbox") == "denied"
    assert tool.called is False  # 执行前边界:工具未被调用


def test_dangerous_schemes_denied() -> None:
    for url in ("gopher://127.0.0.1:6379/_", "dict://x:11211/", "ftp://evil/x", "jar:nested!/a"):
        r = _run(_PassTool(), {"url": url}, allow_domains=["gov.cn", "evil", "x"])
        assert not r.ok and "协议" in (r.error or ""), url


def test_https_scheme_still_allowed() -> None:
    # 协议白名单不误伤正常 https(在域名白名单内)。
    r = _run(_PassTool(), {"url": "https://gov.cn/x"}, allow_domains=["gov.cn"])
    assert r.ok and r.output == "done"


def test_schemeless_url_falls_through_to_domain_check() -> None:
    # 无协议的裸主机串不触发协议规则,仍由域名白名单把关(此处不在白名单 → 拒)。
    r = _run(_PassTool(), {"url": "gov.cn/x"}, allow_domains=["example.com"])
    assert not r.ok and "外联" in (r.error or "")


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


# ---- 缺口1:符号链接逃逸(realpath 容纳检查,纵深,不依赖 argrisk 纯字符串判定)----


def test_realpath_pure_contains_inside_path(tmp_path: Path) -> None:
    """纯函数:工作区内的普通文件/子目录 realpath 后仍在区内 → 不逃逸。"""
    ws = str(tmp_path)
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "a.txt").write_text("x", encoding="utf-8")
    assert _realpath_escapes("sub/a.txt", ws) is False
    assert _realpath_escapes(str(tmp_path / "sub" / "a.txt"), ws) is False
    assert _realpath_escapes("", ws) is False  # 无路径不判逃逸


def test_realpath_pure_detects_escape(tmp_path: Path) -> None:
    """纯函数:解析后真实路径落到工作区外 → 逃逸(绝对路径/上级穿越两形态)。"""
    ws = tmp_path / "ws"
    ws.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    assert _realpath_escapes(str(outside), str(ws)) is True
    assert _realpath_escapes("../outside.txt", str(ws)) is True


def test_symlink_escape_denied(tmp_path: Path) -> None:
    """工作区内一条软链指向区外文件:argrisk 字符串检查放过,realpath 容纳检查拦下。

    跨平台:Windows 建软链需特权,os.symlink 抛 OSError/NotImplementedError → skip(不让无权限
    环境 CI 变红);realpath 容纳逻辑另由上面两条纯函数单测覆盖,不依赖本用例。
    """
    ws = tmp_path / "ws"
    ws.mkdir()
    outside = tmp_path / "outside_secret.txt"
    outside.write_text("classified", encoding="utf-8")
    link = ws / "innocent.txt"
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError):
        pytest.skip("当前平台/权限不支持创建符号链接")

    # 字符串层(argrisk):软链名 innocent.txt 看着区内,旧检查放过。
    from fulcrum.capabilities.toolguard import argrisk

    assert argrisk.path_outside_workspace({"path": "innocent.txt"}, str(ws)) is False
    # 执行器纵深层:realpath 跟随软链 → 解析到区外 → 拒绝执行,工具未触达。
    tool = _RecordingTool()
    r = _run(tool, {"path": str(link)}, workspace=str(ws))
    assert not r.ok and "软链" in (r.error or "")
    assert r.side_effects.get("sandbox") == "denied"
    assert tool.called is False


def test_inside_workspace_symlink_allowed(tmp_path: Path) -> None:
    """区内软链指向区内文件:仍在工作区内 → 不应被误拒(只拦逃逸,不伤合法软链)。"""
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "real.txt").write_text("ok", encoding="utf-8")
    link = ws / "alias.txt"
    try:
        os.symlink(ws / "real.txt", link)
    except (OSError, NotImplementedError):
        pytest.skip("当前平台/权限不支持创建符号链接")
    assert _realpath_escapes(str(link), str(ws)) is False
    r = _run(_PassTool(), {"path": str(link)}, workspace=str(ws))
    assert r.ok and r.output == "done"


# ---- 缺口2:多键 URL 协议绕过(协议白名单覆盖所有目的地键,非仅 url)----


def test_multikey_scheme_bypass_denied() -> None:
    """地址放进 endpoint/webhook/target/to… 等键传非 http/https 协议 → 各自被拦。"""
    cases = [
        {"endpoint": "file:///etc/passwd"},
        {"webhook": "gopher://127.0.0.1:6379/_"},
        {"target": "dict://x:11211/"},
        {"to": "ftp://evil/x"},
        {"callback": "file:/etc/shadow"},  # 单斜杠 file: 也属危险不透明协议
        {"forward_to": "jar:nested!/a"},  # 无 :// 但在危险协议集合
    ]
    for args in cases:
        tool = _RecordingTool()
        r = _run(tool, args, allow_domains=["evil", "x", "127.0.0.1"])
        assert not r.ok and "协议" in (r.error or ""), args
        assert r.side_effects.get("sandbox") == "denied"
        assert tool.called is False, args


def test_multikey_http_in_alt_key_falls_through_to_domain() -> None:
    """非 url 键里放白名单内 https → 协议层放过,仍由域名白名单把关(在白名单 → 放行)。"""
    r = _run(_PassTool(), {"endpoint": "https://gov.cn/x"}, allow_domains=["gov.cn"])
    assert r.ok and r.output == "done"


def test_multikey_benign_colon_values_not_treated_as_scheme() -> None:
    """带冒号的良性值(host:port、时间、邮箱)不应被误判为协议绕过。"""
    for args in (
        {"endpoint": "localhost:6379"},
        {"to": "user@example.com"},
        {"address": "12:30 会议"},
        {"target": "section3"},
    ):
        assert _disallowed_url_scheme(args) is None, args


def test_url_key_scheme_still_denied() -> None:
    """既有 url 键的协议白名单行为不变(回归保护)。"""
    r = _run(_PassTool(), {"url": "file:///etc/passwd"}, allow_domains=["gov.cn"])
    assert not r.ok and "协议" in (r.error or "")


# ── overlong UTF-8 分隔符穿越:执行器端到端(评审 #113)──────────────────────────
# argrisk 纯函数层已覆盖规范逻辑;这里钉**执行边界**层——策略放行后 RestrictedExecutor
# 复用同一口径,Linux(`/`)/Windows(`\`)的 overlong 编码穿越在执行前仍被拒,
# 且正常 Unicode 路径(中文/变音/emoji/全角)不因规范化被误伤。


@pytest.mark.parametrize(
    "path",
    [
        "..%c0%af..%c0%afetc%c0%afpasswd",  # 2 字节 overlong `/`(Linux 形态,基线漏判)
        "..%e0%80%af..%e0%80%afetc%e0%80%afpasswd",  # 3 字节
        "..%f0%80%80%af..%f0%80%80%afetc%f0%80%80%afpasswd",  # 4 字节
        "%c0%ae%c0%ae%c0%afetc%c0%afpasswd",  # 连 `..` 里的点也 overlong
        "..%c0%9c..%c0%9cWindows%c0%9cwin.ini",  # overlong `\`(Windows 形态,0xC0 前导)
        "..%c1%9c..%c1%9cWindows%c1%9csam",  # overlong `\`(0xC1 前导变体)
        "..%25c0%25af..%25c0%25afetc%25c0%25afpasswd",  # 双重编码 overlong
    ],
)
def test_overlong_utf8_traversal_denied_by_executor(path: str) -> None:
    r = _run(_PassTool(), {"path": path})
    assert not r.ok
    assert r.side_effects.get("sandbox") == "denied"


def test_overlong_utf8_escape_to_nonsensitive_denied_by_executor() -> None:
    # 目标非敏感(共享目录普通文件)→ 拦的是**越出工作区**本身,不依赖敏感路径清单。
    r = _run(_PassTool(), {"path": "..%c0%af..%c0%afshared%c0%afbudget.xlsx"})
    assert not r.ok and "越出" in (r.error or "")


@pytest.mark.parametrize(
    "path",
    [
        "报表/2026年Q3.xlsx",  # 中文目录/文件名
        "归档／2026／上半年.xlsx",  # 全角 ／(U+FF0F)是普通字符、非分隔符,不作穿越解读
        "naïve-résumé_2026.pdf",  # 变音拉丁字母
        "📁会议纪要.md",  # emoji 文件名
        "file%20name.txt",  # 合法百分号编码(空格),非 overlong
    ],
)
def test_normal_unicode_path_not_harmed_by_executor(path: str) -> None:
    # 规范化只针对"良性输入绝不出现"的非法 overlong 序列,正常 Unicode 路径不受影响。
    r = _run(_PassTool(), {"path": path})
    assert r.ok and r.output == "done"


def test_windows_style_unicode_path_inside_workspace_ok() -> None:
    # Windows 反斜杠风格的区内路径(工作区前缀判定前统一归一为 `/`)不误伤。
    r = _run(_PassTool(), {"path": r"data\workspace\报表.xlsx"}, workspace="data/workspace")
    assert r.ok and r.output == "done"
