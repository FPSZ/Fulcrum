"""SequenceChainAnalyzer —— 任务链 / 轨迹异常检测,对应赛题目标②。

单个工具调用可能各自合规(读一份文件、向白名单域发一次请求),但**特定顺序的组合**才是
攻击:最典型的「敏感数据读取 → 对外发送」数据外泄链。本分析器在**请求级**动作序列(trace)
上做有序模式匹配,对当前(最新)调用判断它是否构成异常链的"收口动作",产出带置信度的
Finding,交由策略据 `chain_risk_at_least` 分级处置(读取后外发 → 审批;敏感读取后外发 → 阻断)。

确定性、可解释:动作按工具名 + 参数归类(读取 / 外发),复用 argrisk 的敏感路径判定。
窗口暂以"最近 N 步"近似(ToolIntent 尚无时间戳),N 见 `_WINDOW`。
`trace` 是**请求级**序列(见 Context 生命周期说明);跨请求链待 SessionStore port,本实现不涉及。
Finding 的 evidence 带 `intent_id`(= 触发链的当前调用),供策略只对"当前这步"判链,避免误伤。

接口为 async(与 ChainAnalyzer port 一致,为终局接向量库/模型留空间);当前实现纯本地、无 await。
"""

from __future__ import annotations

import re

from ...core.domain import Context, Finding, ToolIntent
from ...core.registry import capability
from . import argrisk

# 动作归类:对工具名做关键词匹配(中英)。
_READ_RE = re.compile(
    r"(read|search|query|fetch|get|list|load|select|读取|查询|检索)", re.IGNORECASE
)
_EXFIL_RE = re.compile(
    r"(send|post|upload|forward|external|http|webhook|email|notify|exfil|sync|push|外发|外传|上传|发送)",
    re.IGNORECASE,
)
# 敏感数据读取(按工具名,补充 argrisk 的敏感路径判定)。
_SENSITIVE_RE = re.compile(
    r"(citizen|personal|secret|credential|confidential|ledger|roster|个人|公民|台账|花名册|凭据|涉密|机密)",
    re.IGNORECASE,
)
# 外发动作的目的地参数键:即便工具名未命中,带这些参数也视为对外动作。
_DEST_KEYS = frozenset(
    {
        "url",
        "to",
        "recipient",
        "recipients",
        "dest",
        "destination",
        "email",
        "endpoint",
        "webhook",
        "target",
        "address",
    }
)
# 回看窗口(步数近似)。当前调用之前的 _WINDOW 步内出现敏感/普通读取即构成链。
_WINDOW = 12


def _is_read(intent: ToolIntent) -> bool:
    return bool(_READ_RE.search(intent.tool_name))


def _is_outbound(intent: ToolIntent) -> bool:
    if _EXFIL_RE.search(intent.tool_name):
        return True
    return any(k in intent.arguments for k in _DEST_KEYS)


def _is_sensitive_read(intent: ToolIntent) -> bool:
    return _is_read(intent) and (
        argrisk.path_sensitive(intent.arguments) or bool(_SENSITIVE_RE.search(intent.tool_name))
    )


@capability("chain_analyzer", "sequence")
class SequenceChainAnalyzer:
    """有序动作链检测。注册名 `sequence`,在 fulcrum.yml 启用。"""

    async def analyze(self, trace: list[ToolIntent], ctx: Context) -> list[Finding]:
        if not trace:
            return []
        current = trace[-1]
        if not _is_outbound(current):
            return []  # 仅在"对外发送"这步收口判链

        window = trace[-(_WINDOW + 1) : -1]  # 当前调用之前、窗口内的历史调用
        reads = [t for t in window if _is_read(t)]
        if not reads:
            return []

        sensitive = any(_is_sensitive_read(t) for t in reads)
        score = 0.85 if sensitive else 0.5
        pattern = "sensitive_read->exfil" if sensitive else "read->exfil"
        return [
            Finding(
                kind="chain.exfiltration",
                score=score,
                evidence={
                    "intent_id": current.intent_id,
                    "pattern": pattern,
                    "severity": "critical" if sensitive else "medium",
                    "read_tools": [t.tool_name for t in reads][:3],
                    "exfil_tool": current.tool_name,
                    "window_steps": _WINDOW,
                },
            )
        ]
