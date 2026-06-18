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

import base64
import binascii
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
# 持久化/长期存储 sink:记忆、知识库、长期事实库。把不可信工具返回原样写进这里 = 记忆投毒,
# 影响未来所有会话的决策。与"对外发送"并列,是任务链的另一类收口动作。
_PERSIST_RE = re.compile(
    r"(remember|memor(y|ize)|recall|persist|knowledge|\bkb\b|长期|记忆|记住|知识库)",
    re.IGNORECASE,
)
# 通用写动作动词(工具名未直说记忆/知识库时,配合目标路径/键判断写入 sink 性质)。
_WRITE_RE = re.compile(
    r"(write|save|store|append|update|upsert|put|记录|写入|保存|存储)", re.IGNORECASE
)
# 承载写入内容的参数键:持久化写入须带内容才有"投毒"意义。
_CONTENT_KEYS = frozenset({"content", "value", "text", "data", "body", "fact", "note", "memory"})
# 回看窗口(步数近似)。当前调用之前的 _WINDOW 步内出现敏感/普通读取即构成链。
_WINDOW = 12
# 跨步污点:外发参数里出现长度 ≥ 此阈值、源自某一步工具返回的连续片段 → 判定污点。
# 阈值取得够长以避免短公共串(如 "true"/url 协议头)误报。
_TAINT_MIN = 12

# 编码外发规避:把上一步读到的敏感量先 Base64/Hex 编码再外发,可绕过原样子串比对。
# 故对外发参数里的编码块就地解码,得到的明文一并参与污点比对。阈值取够长以避免噪声:
# Base64 ≥16 字符(≥12 字节明文)、Hex ≥24 字符(≥12 字节明文),均对齐 _TAINT_MIN。
_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_BLOB = re.compile(r"(?:[0-9a-fA-F]{2}){12,}")


def _decoded_variants(text: str) -> list[str]:
    """抽取外发文本里的 Base64/Hex 块并解码为明文(utf-8,无法解码的丢弃)。

    用于堵「编码后外发」规避:`send(data=base64(secret))` 时原文不含 secret 子串,但解码块含。
    确定性:仅解码格式合法且能落地为 utf-8 的块,失败静默跳过,不猜测。
    """
    out: list[str] = []
    for m in _B64_BLOB.finditer(text):
        blob = m.group()
        try:
            dec = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        text_dec = dec.decode("utf-8", "ignore")
        if text_dec:
            out.append(text_dec)
    for m in _HEX_BLOB.finditer(text):
        try:
            dec = bytes.fromhex(m.group())
        except ValueError:
            continue
        text_dec = dec.decode("utf-8", "ignore")
        if text_dec:
            out.append(text_dec)
    return out


def _args_text(intent: ToolIntent) -> str:
    """外发动作的参数值拼成可比对文本(只取值,键名不参与污点比对)。"""
    return " ".join(str(v) for v in intent.arguments.values())


def _normalize_taint(s: str) -> str:
    """污点比对归一化:抹除所有空白 + casefold。

    挫败"原样外发但大小写不同 / 字符间插空格"这类规避;去空白还顺带让被空格拆进多个
    参数字段的连续敏感量在拼接文本里重新相邻,缩小分片绕过面。
    """
    return "".join(s.split()).casefold()


def _taint_source(intent: ToolIntent, tool_returns: list[str]) -> tuple[str, bool] | None:
    """当前外发参数是否源自某一步工具返回:取返回内容的连续片段在参数文本里命中即判污点。

    归一化(去空白 + casefold)后做**逐位**滑窗子串匹配 —— 此前以步长 4 跳采会漏掉起点不
    对齐的字面子串(实测 'SECRETDATA99' 原样外发却判 None);步长改 1 并归一化后,对齐 /
    大小写 / 插空格三类规避一并堵死。除原样参数文本外,还把参数里的 Base64/Hex 块解码后
    一并作为比对干草堆,堵「编码后外发」规避。返回 (命中的原始返回内容摘要, 是否经编码),
    无则 None。原样命中优先于编码命中。确定性子串匹配,不猜测。
    """
    args_raw = _args_text(intent)
    # (干草堆, 是否经解码);原样在前,确保原样命中优先报告。
    haystacks: list[tuple[str, bool]] = [(_normalize_taint(args_raw), False)]
    haystacks += [(_normalize_taint(dec), True) for dec in _decoded_variants(args_raw)]
    for ret in tool_returns:
        norm = _normalize_taint(ret)
        if len(norm) < _TAINT_MIN:
            continue
        for hay, encoded in haystacks:
            if len(hay) < _TAINT_MIN:
                continue
            for i in range(len(norm) - _TAINT_MIN + 1):
                if norm[i : i + _TAINT_MIN] in hay:
                    return ret.strip()[:80], encoded
    return None


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


def _persist_target(intent: ToolIntent) -> str:
    return str(
        intent.arguments.get("path")
        or intent.arguments.get("key")
        or intent.arguments.get("target")
        or ""
    )


def _is_persist_write(intent: ToolIntent) -> bool:
    """是否把内容写入长期记忆/知识库等持久化 sink(记忆投毒链的收口动作)。

    两条判别,任一成立即可:
    - 工具名本身就是记忆/知识库交互(memory.*/kb.*/knowledge.*/remember…)且带写入内容;
    - 通用写动作(write/save/append…),但目标路径/键指向记忆/知识库。
    后者把目标限定在持久化 sink,正常 `file.write` 到工作区不误触。
    """
    name = intent.tool_name
    has_content = any(k in intent.arguments for k in _CONTENT_KEYS)
    if _PERSIST_RE.search(name) and has_content:
        return True
    return bool(_WRITE_RE.search(name) and _PERSIST_RE.search(_persist_target(intent)))


@capability("chain_analyzer", "sequence")
class SequenceChainAnalyzer:
    """有序动作链检测。注册名 `sequence`,在 fulcrum.yml 启用。"""

    async def analyze(self, trace: list[ToolIntent], ctx: Context) -> list[Finding]:
        if not trace:
            return []
        current = trace[-1]
        outbound = _is_outbound(current)
        # 收口动作有两类:对外发送(外泄链)、写入长期记忆/知识库(记忆投毒链)。
        if not outbound:
            if _is_persist_write(current):
                return self._persistence_findings(current, ctx)
            return []

        findings: list[Finding] = []

        # ① 跨步数据流污点:外发参数确实源自上一步工具返回 —— 比"顺序巧合"更硬的外泄证据。
        taint = _taint_source(current, ctx.tool_returns)
        if taint is not None:
            tainted, encoded = taint
            # 编码后外发是更强的恶意信号(刻意隐藏载荷,不可能是顺序巧合),证据再加重。
            pattern = "tool_return->encode->exfil" if encoded else "tool_return->exfil"
            findings.append(
                Finding(
                    kind="chain.taint_exfiltration",
                    score=0.95 if encoded else 0.9,
                    evidence={
                        "intent_id": current.intent_id,
                        "pattern": pattern,
                        "severity": "critical",
                        "exfil_tool": current.tool_name,
                        "tainted_from": tainted,
                        "encoded": encoded,
                    },
                )
            )

        # ② 顺序模式:窗口内出现(敏感)读取 + 当前外发。
        window = trace[-(_WINDOW + 1) : -1]  # 当前调用之前、窗口内的历史调用
        reads = [t for t in window if _is_read(t)]
        if reads:
            sensitive = any(_is_sensitive_read(t) for t in reads)
            score = 0.85 if sensitive else 0.5
            pattern = "sensitive_read->exfil" if sensitive else "read->exfil"
            findings.append(
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
            )

        return findings

    @staticmethod
    def _persistence_findings(current: ToolIntent, ctx: Context) -> list[Finding]:
        """记忆投毒链:把**源自不可信工具返回**的内容原样写进长期记忆/知识库。

        仅在污点成立(写入内容确实来自上一步工具返回)时收口 —— 把外部内容存进长期库会污染
        未来所有会话的决策,是 AI 推荐投毒 / 持久化记忆投毒的核心动作。评分定在复核档(非硬拦),
        因为「抓取一份正规文档入库」是合法 RAG 流程,语义善恶难由链结构断定,交人工复核更稳妥;
        编码后再写入(刻意隐藏载荷)恶意性更强,评分上调但仍在复核档内。
        """
        taint = _taint_source(current, ctx.tool_returns)
        if taint is None:
            return []
        tainted, encoded = taint
        pattern = "tool_return->encode->persist" if encoded else "tool_return->persist"
        return [
            Finding(
                kind="chain.persistence_poisoning",
                score=0.75 if encoded else 0.6,
                evidence={
                    "intent_id": current.intent_id,
                    "pattern": pattern,
                    "severity": "high",
                    "sink_tool": current.tool_name,
                    "tainted_from": tainted,
                    "encoded": encoded,
                },
            )
        ]
