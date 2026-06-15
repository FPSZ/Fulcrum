"""HeuristicRiskScorer —— 工具调用的固有风险评分(0~1),对应赛题目标②。

按"工具基础风险 + 参数加权"刻画**动作本身**的危险度:敏感/越界文件、危险命令、
外联域名/裸 IP 都会抬升分值。来源信任与归因置信度由 policy 另行结合,本评分不掺入,
保持职责单一(评分=动作危险度,判定=动作危险度×来源×归因)。
"""

from __future__ import annotations

from ...core.domain import Context, ToolIntent
from ...core.registry import capability
from . import argrisk

# 各工具的固有基础风险(无参数时的起点)。含政务 demo 业务工具。
_BASE: dict[str, float] = {
    "shell.exec": 0.6,
    "http.request": 0.4,
    "file.write": 0.45,
    "file.read": 0.25,
    "echo": 0.0,
    # 政务 demo 业务动作
    "doc.read": 0.3,
    "kb.search": 0.1,
    "case.approve": 0.7,
    "funds.disburse": 0.8,
    "citizen.query": 0.45,
    "external.send": 0.6,
    "notify.send": 0.3,
}
_DEFAULT_WORKSPACE = "data/workspace"
# 带文件路径参数的工具 / 带 URL 参数的工具(决定走哪套参数加权)。
_PATH_TOOLS = frozenset({"file.read", "file.write", "doc.read"})
_URL_TOOLS = frozenset({"http.request", "external.send"})


@capability("risk_scorer", "heuristic")
class HeuristicRiskScorer:
    def score(self, intent: ToolIntent, ctx: Context) -> float:
        tool = intent.tool_name
        args = intent.arguments
        score = _BASE.get(tool, 0.3)
        if tool in _PATH_TOOLS:
            if argrisk.path_sensitive(args):
                score += 0.5
            if argrisk.path_outside_workspace(args, _DEFAULT_WORKSPACE):
                score += 0.3
        elif tool in _URL_TOOLS:
            if argrisk.url_host(args):
                score += 0.2
            if argrisk.is_raw_ip(args):
                score += 0.2
        elif tool == "shell.exec":
            if argrisk.command_dangerous(args):
                score += 0.4
        return round(min(score, 1.0), 3)
