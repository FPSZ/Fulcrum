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


def test_destructive_sql_ddl_is_high() -> None:
    # 不可逆 DDL(DROP/TRUNCATE 表/库)经结构化参数下达,command_dangerous 看不到 → 评分独立抬升。
    assert _score("db.query", {"sql": "DROP TABLE citizens"}) >= 0.8
    assert _score("db.query", {"sql": "TRUNCATE TABLE audit_log"}) >= 0.8


def test_unfiltered_bulk_dml_is_high() -> None:
    # 无 WHERE 守卫的整表删除/改写 = 批量不可逆,显著抬升。
    assert _score("db.query", {"sql": "delete from users"}) >= 0.8
    assert _score("db.query", {"statement": "UPDATE accounts SET balance=0"}) >= 0.8


def test_guarded_dml_not_penalized_as_destructive() -> None:
    # 带 WHERE 的定向维护是常规操作,不应被当作破坏性动作加权。
    guarded = _score("db.query", {"sql": "DELETE FROM logs WHERE ts < '2020-01-01'"})
    select = _score("db.query", {"sql": "SELECT * FROM users WHERE id=1"})
    assert guarded == select  # 二者都只吃 base,无破坏性增量


def test_recursive_delete_in_structured_args_is_high() -> None:
    # 递归/通配删除走结构化字段(非 command),command_dangerous 不覆盖,这里补上。
    benign = _score("fs.delete", {"path": "reports", "id": "1"})
    recursive = _score("fs.delete", {"path": "reports", "args": ["rm", "-rf", "/var/log"]})
    assert recursive >= 0.7 and recursive > benign
    assert _score("fs.delete", {"target": "/data/archive/*", "op": "delete"}) >= 0.7


def test_destructive_scan_skips_command_field_no_double_count() -> None:
    # command 字段是 command_dangerous 的职责;破坏性扫描跳过它,避免对同一危险命令重复计分。
    assert _score("shell.exec", {"command": "rm -rf /data"}) == 1.0  # 仅 command_dangerous 一次加权


def test_single_targeted_delete_is_not_destructive() -> None:
    # op=delete 但定向到单条(无通配范围)是正常删除,不抬升为破坏性。
    assert _score("record.delete", {"op": "delete", "id": "draft-123"}) < 0.6
