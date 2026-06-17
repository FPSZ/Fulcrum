"""KeywordRuleDetector —— 多源、可分级的确定性输入风险检测(规则法)。

对应赛题目标①:覆盖用户输入、文档附件、网页内容、知识库检索结果、历史记忆、
工具返回等多源输入,识别六类风险并按"来源信任级 + 直接/间接来源"加权:

    injection       提示注入 / 指令覆盖
    jailbreak       越狱诱导 / 角色绕过
    exfiltration    数据外发 / 隐蔽外联
    sensitive_file  敏感文件 / 密钥凭据访问
    command_exec    系统命令 / 脚本执行
    data_poisoning  数据投毒 / 知识污染
    pii_leak        结构化敏感量泄露(身份证/手机号/邮箱/密钥实值,按命中条数升级)

前六类靠"措辞"识别意图;`pii_leak` 不同——它数的是回复/输入里**真的夹带了多少条**结构化
个人或机密数据(实际号码/邮箱/密钥值)。单条多属正常(用户报自己手机号),批量出现才是
名册级外泄,故按命中条数升级严重度。出口闸门借此拦住"把市民名册原样吐出来"这类泄露——
仅凭关键词规则(sensitive_file 只识"提到了凭据")是抓不住的。

确定性、可解释、低延迟,作为第一层防线;LLM-judge 在 P3 作为后置增强叠加(见路线图)。
每个命中产出一条 Finding:`score`∈[0,1],`evidence.severity`∈{low,medium,high,critical},
并附命中规则、来源信息,供归因与审计取证使用。
"""

from __future__ import annotations

import re

from ...core.domain import Context, Finding, SourceSpan, SourceType, TrustLevel
from ...core.registry import capability

# 六类风险 -> (固有严重度基准 0~1, 正则模式集)。同类多模式命中合并为一条 Finding。
# 模式中英并重,面向政企中文场景;均为可解释的确定性规则。
_CATEGORIES: dict[str, tuple[float, tuple[str, ...]]] = {
    "injection": (
        0.75,
        (
            r"ignore (the )?(previous|above|prior|preceding)",
            r"disregard (the )?(instructions|above|previous|rules)",
            r"override (the )?(instructions|system|rules)",
            r"forget (everything|all|previous|the above)",
            r"new instructions?\s*[:：]",
            r"(reveal|show|print|repeat) (the )?(system )?prompt",
            r"忽略(以上|之前|上述|前面|刚才|前文)",
            r"无视(以上|之前|上述|规则|指令|前面)",
            r"不要(遵守|理会|遵循|管)",
            r"覆盖(指令|规则|系统设定|设置)",
            r"(新的|以下|真正的)指令\s*[:：]",
            r"现在开始\s*[,，]?\s*你",
            r"(泄露|打印|输出|重复)(你的)?(系统)?提示词",
        ),
    ),
    "jailbreak": (
        0.8,
        (
            r"you are now",
            r"developer mode",
            r"do anything now",
            r"(without|no) (any )?(restrictions|limitations|rules|filter)",
            r"bypass (the )?(safety|filter|guardrails?|审查)",
            r"pretend (you are|to be) .{0,20}(unrestricted|no rules)",
            r"你现在(是|要扮演|将)",
            r"开发者模式",
            r"越狱模式|进入越狱",
            r"不受(任何)?限制",
            r"绕过(安全|过滤|审查|限制|策略)",
            r"扮演一个(不受|没有).{0,8}(限制|约束)",
        ),
    ),
    "exfiltration": (
        0.85,
        (
            r"exfiltrate",
            r"(send|upload|post|email|forward)\s+.{0,24}(to|至|给)\s+.{0,30}(http|external|外部|邮箱|@)",
            r"读取并(发送|外发|上传|回传|提交)",
            r"(外发|外传|回传|泄露|转发|上报)\s*(给|到|至)",
            r"(发送|提交|上传)\s*(到|给)\s*.{0,20}(外部|http|邮箱|服务器)",
            r"curl\s+.{0,40}-d|POST\s+https?://",
        ),
    ),
    "sensitive_file": (
        0.7,
        (
            r"/etc/(passwd|shadow)",
            r"id_rsa|\.ssh/|\.env\b|\.pem\b|\.key\b",
            r"(private[_ ]?key|api[_ ]?key|secret[_ ]?key|access[_ ]?token|credentials?)",
            r"(密钥|私钥|口令|凭据|凭证|机密|涉密|账号密码)",
        ),
    ),
    "command_exec": (
        0.8,
        (
            r"rm\s+-rf",
            r"\b(curl|wget)\s+https?://",
            r"(bash|sh|zsh|powershell|cmd)\s+-c|/bin/sh\b",
            r"(os\.system|subprocess\.|\bexec\(|\beval\()",
            r"base64\s+-d|chmod\s+777|nc\s+-e|reverse shell",
            r"(执行|运行|调用)(系统)?(命令|脚本|shell|cmd)",
            r"删除(所有|全部|整个)(文件|数据|目录)",
        ),
    ),
    "data_poisoning": (
        0.6,
        (
            r"this is the (only )?correct answer",
            r"always (recommend|choose|select|answer|reply)",
            r"the (official|approved) (policy|answer) is now",
            r"(标准|正确|唯一)答案(是|为|就是)",
            r"以后(都|一律|请|要)(推荐|选择|回答|认为|记住)",
            r"永远(推荐|选择|相信|认为)",
            r"记住(这条|这个|以下|此)规则",
        ),
    ),
}

# 结构化敏感量:实际数值/令牌(而非仅"提到凭据"的措辞)。与 sensitive_file 互补——
# 此类命中表示文本里**真的夹带了**个人或机密数据,是出口名册外泄的直接证据。
_PII_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)"),  # 身份证号(18 位)
    re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"),  # 手机号(11 位)
    re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"),  # 邮箱
    re.compile(  # 显式密钥/口令赋值(带实值)
        r"(?i)(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
        r"密码|口令|密钥|凭据|凭证)\s*[:=]\s*\"?[^\s\"]{3,}"
    ),
)


def _pii_score(count: int) -> float:
    """命中条数 → 严重度基准:单条(0.4,多属正常)→ 批量名册外泄(0.85,critical)。"""
    if count >= 3:
        return 0.85
    if count == 2:
        return 0.6
    return 0.4


# 来源信任级 -> 乘子:不可信来源命中风险最高,用户直述同样措辞风险较低。
_TRUST_MUL: dict[TrustLevel, float] = {
    TrustLevel.UNTRUSTED: 1.0,
    TrustLevel.SEMI_TRUSTED: 0.8,
    TrustLevel.TRUSTED: 0.55,
}

# 间接来源(藏在文档/网页/检索/记忆/工具返回/插件清单里)是"间接指令污染"的主战场,额外加权。
_INDIRECT_SOURCES: frozenset[SourceType] = frozenset(
    {
        SourceType.DOCUMENT,
        SourceType.WEBPAGE,
        SourceType.RETRIEVAL,
        SourceType.MEMORY,
        SourceType.TOOL_RETURN,
        SourceType.PLUGIN_MANIFEST,
    }
)
_INDIRECT_BOOST = 0.15

# 启动时编译一次(忽略大小写),热路径零编译开销。
_COMPILED: dict[str, tuple[float, tuple[re.Pattern[str], ...]]] = {
    cat: (weight, tuple(re.compile(p, re.IGNORECASE) for p in pats))
    for cat, (weight, pats) in _CATEGORIES.items()
}


def _severity(score: float) -> str:
    if score >= 0.8:
        return "critical"
    if score >= 0.6:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"


@capability("detector", "keyword_rules")
class KeywordRuleDetector:
    """多源规则检测器。注册名沿用 `keyword_rules`,装配清单无需改动。"""

    name = "keyword_rules"

    def detect(self, spans: list[SourceSpan], ctx: Context) -> list[Finding]:
        findings: list[Finding] = []
        for span in spans:
            text = span.excerpt
            trust_mul = _TRUST_MUL.get(span.trust_level, 1.0)
            indirect = span.source_type in _INDIRECT_SOURCES
            for cat, (weight, patterns) in _COMPILED.items():
                matched = [p.pattern for p in patterns if p.search(text)]
                if not matched:
                    continue
                raw = weight * trust_mul + (_INDIRECT_BOOST if indirect else 0.0)
                score = round(min(raw, 1.0), 3)
                findings.append(
                    Finding(
                        kind=cat,
                        score=score,
                        evidence={
                            "source_id": span.source_id,
                            "source_type": span.source_type,
                            "trust_level": span.trust_level,
                            "severity": _severity(score),
                            "matched_rules": matched,
                            "indirect_source": indirect,
                        },
                    )
                )
            # 结构化敏感量:按命中条数(身份证/手机/邮箱/密钥实值)升级,而非固定权重。
            pii_hits = sum(len(p.findall(text)) for p in _PII_PATTERNS)
            if pii_hits:
                raw = _pii_score(pii_hits) * trust_mul + (_INDIRECT_BOOST if indirect else 0.0)
                score = round(min(raw, 1.0), 3)
                findings.append(
                    Finding(
                        kind="pii_leak",
                        score=score,
                        evidence={
                            "source_id": span.source_id,
                            "source_type": span.source_type,
                            "trust_level": span.trust_level,
                            "severity": _severity(score),
                            "pii_hits": pii_hits,
                            "indirect_source": indirect,
                        },
                    )
                )
        return findings
