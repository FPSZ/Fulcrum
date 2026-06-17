"""HeuristicRiskScorer —— 工具调用的固有风险评分(0~1),对应赛题目标②。

风险 = **工具基础风险**(base_risk,由管线从 Tool 盖戳到 intent)+ **参数风险加权**。
参数风险**按出现了哪类危险参数判定,与工具名无关**:有 path 参就查路径敏感/越界、有 url 参
就查外联/裸 IP/内网 SSRF、有 command 参就查危险命令。因此**加工具零改本评分器**——基础风险写在
工具上,参数口径与 yaml_policy 的事实(argrisk)同源。来源信任与归因置信度由 policy 另行
结合(评分=动作危险度,判定=动作危险度×来源×归因),职责单一。
"""

from __future__ import annotations

from ...core.domain import Context, ToolIntent
from ...core.registry import capability
from . import argrisk

# 工具未声明 base_risk(或工具未知)时的兜底基础风险。
_DEFAULT_BASE = 0.3
# 参数越界判定用的默认工作区(评分是启发式近似;权威边界由 policy 按其 yaml workspace 判定)。
_DEFAULT_WORKSPACE = "data/workspace"


@capability("risk_scorer", "heuristic")
class HeuristicRiskScorer:
    def score(self, intent: ToolIntent, ctx: Context) -> float:
        args = intent.arguments
        score = intent.base_risk if intent.base_risk is not None else _DEFAULT_BASE
        # 路径类参数:敏感路径 / 越出工作区(无 path 参时 argrisk 均返回 False,自然不加权)。
        if argrisk.path_sensitive(args):
            score += 0.5
        if argrisk.path_outside_workspace(args, _DEFAULT_WORKSPACE):
            score += 0.3
        # URL 类参数:有外联即抬升,裸 IP 再加,指向内网/云元数据(SSRF)再加。
        if argrisk.url_host(args):
            score += 0.2
            if argrisk.is_raw_ip(args):
                score += 0.2
            if argrisk.url_is_internal(args):
                score += 0.3
        # 命令类参数:命中危险片段才加权。
        if argrisk.command_dangerous(args):
            score += 0.4
        return round(min(score, 1.0), 3)
