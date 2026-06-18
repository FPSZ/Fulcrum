"""RoleTrustLabeler —— 真·多源信任标注(来源归因总线的第一环),对应赛题目标①④。

把一次 ModelRequest 拆成带「来源类型 + 信任级别」的 SourceSpan,供检测/归因/策略下游消费。
相对 passthrough 桩做两件真正的事:

1. **按角色正确归类**:system=系统提示(可信)、user=用户(可信)、assistant=模型既往输出
   (半可信)、tool/function=工具返回(不可信)。passthrough 把 system/assistant 一律误标为
   不可信工具返回,这里修正。未知角色按最不可信处理(fail-closed)。

2. **嵌入式来源抽取(间接指令污染主战场)**:真实智能体常把检索结果/网页/文档/历史记忆
   以 `<context>…</context>`、`[文档]…[/文档]`、`【检索结果】…【/检索结果】` 等形式**夹带**在
   一条 user/system 消息里回灌给模型。本标注器把这些块单独切成 DOCUMENT/WEBPAGE/RETRIEVAL/
   MEMORY + UNTRUSTED 的 span,使检测器的「间接来源加权」真正生效——同一句注入,藏在文档里
   比用户直述风险更高,从而被分级处置拦下。承载消息的残余文本仍保留其角色信任级。

确定性、可解释、低延迟。请求自带的 `req.sources`(已预标注)原样并入。
"""

from __future__ import annotations

import hashlib
import re

from ...core.domain import ModelRequest, SourceSpan, SourceType, TrustLevel
from ...core.registry import capability

# 消息角色 -> (来源类型, 信任级别)。
_ROLE_MAP: dict[str, tuple[SourceType, TrustLevel]] = {
    "system": (SourceType.SYSTEM, TrustLevel.TRUSTED),
    "user": (SourceType.USER, TrustLevel.TRUSTED),
    "assistant": (SourceType.ASSISTANT, TrustLevel.SEMI_TRUSTED),
    "tool": (SourceType.TOOL_RETURN, TrustLevel.UNTRUSTED),
    "function": (SourceType.TOOL_RETURN, TrustLevel.UNTRUSTED),
}
# 未知/缺失角色:fail-closed,按最不可信处理。
_UNKNOWN_ROLE: tuple[SourceType, TrustLevel] = (SourceType.TOOL_RETURN, TrustLevel.UNTRUSTED)

# 嵌入块标签(小写,中英并重)-> 来源类型。夹带的外部内容一律视为 UNTRUSTED。
_TAG_TYPE: dict[str, SourceType] = {
    "document": SourceType.DOCUMENT,
    "doc": SourceType.DOCUMENT,
    "file": SourceType.DOCUMENT,
    "attachment": SourceType.DOCUMENT,
    "文档": SourceType.DOCUMENT,
    "附件": SourceType.DOCUMENT,
    "webpage": SourceType.WEBPAGE,
    "web": SourceType.WEBPAGE,
    "url": SourceType.WEBPAGE,
    "网页": SourceType.WEBPAGE,
    "retrieval": SourceType.RETRIEVAL,
    "context": SourceType.RETRIEVAL,
    "kb": SourceType.RETRIEVAL,
    "检索": SourceType.RETRIEVAL,
    "资料": SourceType.RETRIEVAL,
    "知识库": SourceType.RETRIEVAL,
    "memory": SourceType.MEMORY,
    "history": SourceType.MEMORY,
    "记忆": SourceType.MEMORY,
    "历史": SourceType.MEMORY,
    "tool_result": SourceType.TOOL_RETURN,
    "工具返回": SourceType.TOOL_RETURN,
}

# 标签可选集合(长标签优先,避免 "doc" 抢先匹配 "document")。
_TAG_ALT = "|".join(re.escape(t) for t in sorted(_TAG_TYPE, key=len, reverse=True))
# RAG 框架常用的标记行定界:3+ 个 - 或 = 组成的分隔线。
_MARK = r"[-=]{3,}"
# 四种成对定界:<tag>…</tag>  /  [tag]…[/tag]  /  【tag】…【/tag】  /
# ---BEGIN tag--- … ---END tag---(LangChain/LlamaIndex 风格的检索块包裹)。
# 每个正则:group(1)=标签名,group(2)=块内容;\1 反向引用确保开闭标签一致。
_STYLE_RES: tuple[re.Pattern[str], ...] = (
    re.compile(rf"<\s*({_TAG_ALT})\s*>(.*?)<\s*/\s*\1\s*>", re.IGNORECASE | re.DOTALL),
    re.compile(rf"\[\s*({_TAG_ALT})\s*\](.*?)\[\s*/\s*\1\s*\]", re.IGNORECASE | re.DOTALL),
    re.compile(rf"【\s*({_TAG_ALT})\s*】(.*?)【\s*/\s*\1\s*】", re.IGNORECASE | re.DOTALL),
    re.compile(
        rf"{_MARK}\s*begin\s+({_TAG_ALT})\s*{_MARK}(.*?){_MARK}\s*end\s+\1\s*{_MARK}",
        re.IGNORECASE | re.DOTALL,
    ),
)


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _span(source_type: SourceType, trust: TrustLevel, text: str) -> SourceSpan:
    return SourceSpan(
        source_type=source_type,
        trust_level=trust,
        content_hash=_hash(text),
        excerpt=text[:200],
    )


def _extract_embedded(content: str) -> tuple[list[tuple[SourceType, str]], str]:
    """抽出消息里夹带的来源块。返回 (块列表[(来源类型, 块内文本)], 去掉块后的残余文本)。"""
    blocks: list[tuple[int, int, SourceType, str]] = []
    for style in _STYLE_RES:
        for m in style.finditer(content):
            source_type = _TAG_TYPE.get(m.group(1).lower())
            if source_type is not None:
                blocks.append((m.start(), m.end(), source_type, m.group(2)))
    if not blocks:
        return [], content

    blocks.sort(key=lambda b: b[0])
    embedded: list[tuple[SourceType, str]] = []
    residual: list[str] = []
    cursor = 0
    for start, end, source_type, inner in blocks:
        if start < cursor:  # 与已取块重叠(嵌套/交叠)→ 跳过,保留先到者
            continue
        residual.append(content[cursor:start])
        cursor = end
        embedded.append((source_type, inner.strip()))
    residual.append(content[cursor:])
    return embedded, "".join(residual)


@capability("labeler", "role_trust")
class RoleTrustLabeler:
    """按角色 + 嵌入来源标注信任级。注册名 `role_trust`,在 fulcrum.yml 启用。"""

    def label(self, req: ModelRequest) -> list[SourceSpan]:
        spans: list[SourceSpan] = list(req.sources)  # 预标注来源原样并入
        for msg in req.messages:
            base_type, base_trust = _ROLE_MAP.get(msg.role, _UNKNOWN_ROLE)
            embedded, residual = _extract_embedded(msg.content)
            for source_type, inner in embedded:
                if inner:  # 夹带的外部内容:一律不可信
                    spans.append(_span(source_type, TrustLevel.UNTRUSTED, inner))
            stripped = residual.strip()
            if stripped:
                # 承载文本(如用户真正的提问)保留其角色信任级
                spans.append(_span(base_type, base_trust, stripped))
            elif not embedded:
                # 整条消息为空:仍产出一个 span,保证可审计、与桩行为一致
                spans.append(_span(base_type, base_trust, msg.content))
        return spans
