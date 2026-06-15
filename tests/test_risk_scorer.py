"""HeuristicRiskScorer:动作固有风险评分。"""

from __future__ import annotations

from fulcrum.capabilities.toolguard.heuristic import HeuristicRiskScorer
from fulcrum.core.domain import Context, ToolIntent

_CTX = Context(session_id="s")
_SCORER = HeuristicRiskScorer()


def _score(tool: str, args: dict) -> float:
    return _SCORER.score(ToolIntent(session_id="s", tool_name=tool, arguments=args), _CTX)


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
