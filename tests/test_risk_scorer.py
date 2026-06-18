"""HeuristicRiskScorer:动作固有风险评分。"""

from __future__ import annotations

from fulcrum.capabilities.toolguard.heuristic import HeuristicRiskScorer
from fulcrum.core.domain import Context, ToolIntent

_CTX = Context(session_id="s")
_SCORER = HeuristicRiskScorer()

# 各工具的固有基础风险(评分器不再枚举工具名;实运行时由管线从 Tool.base_risk 盖戳,
# 此处显式提供以隔离测试评分器本身:评分 = base + 参数加权)。
_BASE = {"echo": 0.0, "file.read": 0.25, "file.write": 0.45, "http.request": 0.4, "shell.exec": 0.6}


def _score(tool: str, args: dict) -> float:
    intent = ToolIntent(
        session_id="s", tool_name=tool, arguments=args, base_risk=_BASE.get(tool, 0.3)
    )
    return _SCORER.score(intent, _CTX)


def test_echo_is_zero_risk() -> None:
    assert _score("echo", {"text": "hi"}) == 0.0


def test_sensitive_file_read_is_high() -> None:
    assert _score("file.read", {"path": "/etc/passwd"}) >= 0.6


def test_workspace_file_read_is_low() -> None:
    assert _score("file.read", {"path": "data/workspace/notice.txt"}) < 0.4


def test_dangerous_command_is_high() -> None:
    assert _score("shell.exec", {"command": "rm -rf /data"}) >= 0.8


def test_raw_ip_http_higher_than_domain() -> None:
    assert _score("http.request", {"url": "http://10.0.0.5/x"}) > _score(
        "http.request", {"url": "http://gov.cn/x"}
    )


def test_internal_ssrf_url_higher_than_public_domain() -> None:
    # 指向云元数据/内网的 URL 比普通公网域名风险更高(SSRF 借智能体打内部面)。
    assert _score("http.request", {"url": "http://169.254.169.254/latest/meta-data/"}) > _score(
        "http.request", {"url": "https://gov.cn/x"}
    )
