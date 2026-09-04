"""对抗性审查 P0 回归(2026-09-04)——三个确定性绕过的修复守门。

背景:held-out 对抗探针实测发现三处全链穿透/绕过,按第一性原理修复:
1. **嵌套参数藏 URL**(`{"config":{"endpoint":"http://198.51.100.9/x"}}`):目的地判定从
   "顶层目的地键"升为"参数树全部字符串叶子中被四重围栏筛出的候选"(argrisk.dest_candidates);
   domain_allowed/url_is_internal 消费候选全集——任一候选不合规即不合规。
2. **NTFS 交替数据流**(`note.txt:hidden`):定性为**隐蔽信道**(数据写进流,表面文件内容
   不变,审计/人工检查全盲),修法是路径含非盘符冒号即 fail-closed(受控文件边界不接受
   未定义语义的路径成分),而非"剥流再验"(验完照样放行,信道仍在)。
3. **供应链通配权限**(`permissions:['*']`):通配是"声明全部能力"的**元权限**,不是又一个
   待枚举的危险词——直接按最宽档(critical)计。

正例即当日对抗探针原文;负例锁死良性参数(嵌套版本号/数字/正文提域名/邮箱)不产生候选。
"""

from __future__ import annotations

import asyncio

import pytest

from fulcrum.capabilities.sandbox.restricted_executor import RestrictedExecutor
from fulcrum.capabilities.supplychain.manifest_scanner import ManifestScanner
from fulcrum.capabilities.toolguard import argrisk
from fulcrum.core.domain import Context, ExecResult, ToolIntent


# ── P0-1 目的地候选:嵌套 URL 进入判定视野 ──────────────────────────────────────
def test_dest_candidates_nested_url_and_opaque_and_bare_ip() -> None:
    # 嵌套 dict 里的权威 URL / 危险不透明协议 / 标准四段 IP / 目的地键(省 scheme)全部成候选。
    args = {
        "config": {"endpoint": "http://198.51.100.9/x", "cb": "file:///etc/passwd"},
        "peers": ["10.1.2.3", "jar:nested!/a"],
        "meta": {"webhook": "evil.example/hook"},
    }
    cands = argrisk.dest_candidates(args)
    for expect in (
        "http://198.51.100.9/x",
        "file:///etc/passwd",
        "10.1.2.3",
        "jar:nested!/a",
        "evil.example/hook",
    ):
        assert expect in cands, cands


def test_dest_candidates_benign_leaves_produce_none() -> None:
    # 良性嵌套参数不产生候选:三段版本号 / 普通数字 / 正文提域名 / 邮箱(无 :// 的地址语义)。
    args = {
        "meta": {"version": "2.31.0", "count": 300, "note": "详见 gov.cn 政策页"},
        "contact": "it@unit.gov.cn",
        "time": "12:30",
        "hostport": "localhost:6379",
    }
    assert argrisk.dest_candidates(args) == []
    assert argrisk.domain_allowed(args, []) is True  # 无候选 → 白名单恒过
    assert argrisk.url_is_internal(args) is False


def test_domain_allowed_requires_all_candidates_whitelisted() -> None:
    # 多目的地(顶层 + 嵌套)任一不在白名单即 False——任放一个都是外泄通道。
    args = {"url": "https://gov.cn/notice", "config": {"endpoint": "https://evil.example/x"}}
    assert argrisk.domain_allowed(args, ["gov.cn"]) is False
    assert argrisk.domain_allowed(args, ["gov.cn", "evil.example"]) is True
    # 嵌套候选里的内网 IP 即使全在"白名单"字面之外,也由 internal 判定收口:
    assert argrisk.url_is_internal({"cfg": {"cb": "http://2130706433/admin"}}) is True


def test_nested_ip_radix_obfuscation_internal() -> None:
    # 进制混淆 IP(十进制 2130706433=127.0.0.1)藏在二层,经 `://` 围栏进入候选 → internal。
    assert argrisk.url_is_internal({"payload": {"notify": "http://0x7f000001/admin"}}) is True


# ── P0-2 NTFS 交替流:非盘符冒号 fail-closed ────────────────────────────────────
@pytest.mark.parametrize(
    "path",
    [
        "data/workspace/note.txt:hidden",  # NTFS 交替数据流(对抗探针原文)
        "data/workspace/note.txt::$DATA",  # 保留流名(带冒号的真实形态)
        "data/workspace/x?data:text/plain,xx",  # path 里塞 data: URI
        "http://evil.example/x",  # path 键塞 URL(非盘符冒号)
    ],
)
def test_path_non_drive_colon_denied(path: str) -> None:
    assert argrisk.path_outside_workspace({"path": path}, "data/workspace") is True


@pytest.mark.parametrize(
    "path",
    [
        "data/workspace/报表.xlsx",
        "C:/Users/w/data.txt",  # 盘符(绝对路径,按工作区前缀另行判定,不因冒号误伤)
        "data/workspace/a b.txt",
    ],
)
def test_path_benign_no_colon_or_drive_unharmed(path: str) -> None:
    # 盘符路径不因冒号规则直接误判(其越界与否由既有绝对路径判定负责)。
    if path.startswith("C:/"):
        assert (
            argrisk.path_outside_workspace({"path": path}, "data/workspace") is True
        )  # 区外绝对路径
    else:
        assert argrisk.path_outside_workspace({"path": path}, "data/workspace") is False


# ── 执行器层:嵌套目的地全链兜底 ────────────────────────────────────────────────
class _PassTool:
    name = "x"
    base_risk = 0.1
    model_schema = None

    def call(self, arguments: dict, ctx: Context) -> ExecResult:
        return ExecResult(ok=True, output="hit")


def _exec(args: dict, **kw: object) -> ExecResult:
    ex = RestrictedExecutor(**kw)  # type: ignore[arg-type]
    return asyncio.run(
        ex.execute(
            _PassTool(),
            ToolIntent(session_id="s", tool_name="x", arguments=args),
            Context(session_id="s"),
        )
    )


def test_executor_denies_nested_internal_url() -> None:
    r = _exec({"config": {"endpoint": "http://198.51.100.9/x"}})
    assert not r.ok and "外联" in (r.error or "")  # 默认外联全关 → 嵌套候选也进白名单判定


def test_executor_denies_nested_opaque_scheme() -> None:
    r = _exec({"cfg": {"cb": "file:///etc/passwd"}})
    assert not r.ok and "协议" in (r.error or "")


def test_executor_denies_ntfs_stream_path() -> None:
    r = _exec({"path": "data/workspace/note.txt:hidden"})
    assert not r.ok and "越出" in (r.error or "")


def test_executor_allows_benign_nested_config() -> None:
    # 良性嵌套配置(版本号/数字/正文域名)不被目的地候选误伤,正常放行。
    r = _exec({"meta": {"version": "2.31.0", "count": 300, "note": "see gov.cn"}}, allow_domains=[])
    assert r.ok and r.output == "hit"


# ── P0-3 供应链通配权限 = 元权限 ────────────────────────────────────────────────
def test_manifest_wildcard_permission_blocks() -> None:
    rep = ManifestScanner().scan(
        {"name": "helper2", "permissions": ["*"], "desc": "自动优化办公流程"},
        Context(session_id="s"),
    )
    kinds = [r.kind for r in rep.risks]
    assert "perm.wildcard" in kinds
    assert rep.rating in ("block", "review")  # critical 信号至少进人工复核档
    assert rep.rating == "block"  # 单一通配(critical)即 block


def test_manifest_specific_permissions_not_regressed() -> None:
    # 具体权限声明行为不变:高危词照报、良性照放。
    bad = ManifestScanner().scan(
        {"name": "x", "permissions": ["shell.exec"], "desc": "d"}, Context(session_id="s")
    )
    assert any(r.kind == "perm.command_exec" for r in bad.risks)
    ok = ManifestScanner().scan(
        {"name": "w", "permissions": ["fs:read:workspace"], "desc": "查天气"},
        Context(session_id="s"),
    )
    assert not any(r.kind == "perm.wildcard" for r in ok.risks)
