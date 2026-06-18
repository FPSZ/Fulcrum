"""HeuristicRiskScorer —— 工具调用的固有风险评分(0~1),对应赛题目标②。

风险 = **工具基础风险**(base_risk,由管线从 Tool 盖戳到 intent)+ **参数风险加权**。
参数风险**按出现了哪类危险参数判定,与工具名无关**:有 path 参就查路径敏感/越界、有 url 参
就查外联/裸 IP/内网 SSRF、有 command 参就查危险命令。因此**加工具零改本评分器**——基础风险写在
工具上,参数口径与 yaml_policy 的事实(argrisk)同源。来源信任与归因置信度由 policy 另行
结合(评分=动作危险度,判定=动作危险度×来源×归因),职责单一。
"""

from __future__ import annotations

import re

from ...core.domain import Context, ToolIntent
from ...core.registry import capability
from . import argrisk

# 工具未声明 base_risk(或工具未知)时的兜底基础风险。
_DEFAULT_BASE = 0.3
# 参数越界判定用的默认工作区(评分是启发式近似;权威边界由 policy 按其 yaml workspace 判定)。
_DEFAULT_WORKSPACE = "data/workspace"

# ── 破坏性 / 不可逆动作识别(评分轴,补 command_dangerous 的盲区)──────────────
# command_dangerous 只看 shell `command` 串;但结构化销毁——SQL `DROP`/无 WHERE 的批量
# `DELETE`/`UPDATE`、通配递归删除、op=delete+通配范围——走的是结构化参数,不经 shell。
# 这类动作**不可逆且影响面大**,固有风险应单独抬升,经 policy 的 `risk_at_least` 升级处置。
# 只扫结构化参数,**跳过 command 类字段**(那是 command_dangerous 的职责,避免重复计分)。
_SKIP_KEYS: frozenset[str] = frozenset(
    {"command", "cmd", "cmdline", "shell", "script", "bash", "powershell"}
)
_OP_KEYS: frozenset[str] = frozenset({"op", "operation", "action", "method", "mode", "verb"})
_DESTRUCTIVE_OPS: frozenset[str] = frozenset(
    {"delete", "del", "remove", "drop", "truncate", "purge", "destroy", "erase", "wipe", "format"}
)
# 不可逆 DDL:DROP/TRUNCATE 表/库/schema 等。
_DDL = re.compile(r"(?i)\b(?:drop|truncate)\s+(?:table|database|schema|index|view|tablespace)\b")
# 无 WHERE 守卫的批量 DML(整表删除/改写);带 WHERE 的定向维护不算。
_DML = re.compile(r"(?i)\b(?:delete\s+from\s+\S+|update\s+\S+\s+set)\b[^;]*?(?:;|$)")
# 递归/通配删除(结构化字段里出现,如 args 列表、target 路径)。
_RECURSIVE_DEL = re.compile(
    r"(?i)\b(?:rm|del|erase|remove|rmdir|rd|unlink|delete|drop|purge|format)\b"
    r"[^\n]*?(?:\s-r\b|\s-rf\b|\s-fr\b|--recursive|/s\b|\*\.\*|[\\/]\*|\*$)"
)
# 通配/全量范围标记(与显式破坏性 op 字段联合判定)。
_SCOPE = re.compile(r"(?i)(?:\*|--recursive|\ball\b|全部|所有|通配)")
# 破坏性动作风险增量:不可逆批量 DB 操作最高,递归/通配删除次之。
_DESTRUCTIVE_DELTA: dict[str, float] = {
    "sql_ddl": 0.5,
    "sql_unfiltered": 0.5,
    "recursive_delete": 0.4,
    "destructive_op": 0.4,
}


def _arg_strings(args: dict) -> list[str]:
    """收集参与破坏性判定的字符串参数值(跳过 command 类字段;列表逐项展开)。"""
    out: list[str] = []
    for key, value in args.items():
        if key.lower() in _SKIP_KEYS:
            continue
        if isinstance(value, str):
            out.append(value)
        elif isinstance(value, (list, tuple)):
            out.extend(v for v in value if isinstance(v, str))
    return out


def _destructive_kind(args: dict) -> str | None:
    """识别破坏性/不可逆动作的子类;无则 None。与 command_dangerous 不重叠(跳过命令字段)。"""
    text = " ".join(_arg_strings(args))
    if _DDL.search(text):
        return "sql_ddl"
    if any("where" not in m.group(0).lower() for m in _DML.finditer(text)):
        return "sql_unfiltered"
    if _RECURSIVE_DEL.search(text):
        return "recursive_delete"
    has_destructive_op = any(
        isinstance(v, str) and k.lower() in _OP_KEYS and v.strip().lower() in _DESTRUCTIVE_OPS
        for k, v in args.items()
    )
    if has_destructive_op and _SCOPE.search(text):
        return "destructive_op"
    return None


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
        # 破坏性/不可逆动作(结构化销毁:DROP/无 WHERE 批量 DML/递归通配删除)单独抬升。
        destructive = _destructive_kind(args)
        if destructive is not None:
            score += _DESTRUCTIVE_DELTA[destructive]
        return round(min(score, 1.0), 3)
