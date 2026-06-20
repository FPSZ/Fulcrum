"""出口侧自披露检测器 —— 抓智能体把**自身的安全策略原文 / 可调工具清单**吐给用户。

定位:补出口盲区(corpus 差距报告 §3 P2#10 的两个未覆盖子类)。`keyword_rules.pii_leak`
数的是身份证/手机/邮箱这类**结构化敏感量**;`secret_egress`(另条线)抓**凭据/系统提示**。
都漏掉两类"元信息自披露":

  policy_leak     智能体复述自己的访问控制策略原文(白名单域 / chain_risk 阈值 / workspace
                  根 / 敏感路径拦截规则)。泄露防护规则本身 = 给攻击者递上绕过地图,critical。
  tool_list_leak  智能体枚举自己可调用的工具清单(file.read、shell.exec、external.send…)。
                  暴露可达动作面 = 攻击侦察的第一步,记 high(待人工复核,非直接拦死)。

两类都用**双条件**判定(披露框架词 + ≥2 个具体证据),避免误伤"问策略/问能做什么"的良性
对话:群众问"低保政策标准"、"你能怎么帮我"既无策略规则标记、也无点分工具标识,不命中。

出口闸门(`screen_output`)据分级处置:policy_leak 0.85→拦截不回传;tool_list_leak 0.65→
标注待人工复核。命中即说明回复把"我怎么防你/我能调什么"原样吐了出去。
"""

from __future__ import annotations

import re

from ...core.domain import Context, Finding, SourceSpan
from ...core.normalize import normalize
from ...core.registry import capability

# ── policy_leak:披露访问控制策略原文 ────────────────────────────────────────
# 框架词:把"策略"当对象复述(策略原文/规则/配置)或自陈"我(的/当前的)…策略"。
_POLICY_FRAME = re.compile(
    r"(?:访问控制|安全|防护|过滤|拦截)?策略(?:原文|规则|配置|内容|如下|是)"
    r"|我(?:当前)?的[^,。;\n]{0,8}策略"
    r"|(?:security|access[\- ]?control)\s+polic"
    r"|policy\s+(?:rules?|text|config)",
    re.IGNORECASE,
)
# 具体规则标记:策略配置里才会出现的硬词;要 ≥2 个不同,良性"问政策"不会同时撞上。
_POLICY_MARKERS = (
    re.compile(r"chain_risk"),
    re.compile(r"白名单域|非白名单|allowlist|whitelist", re.IGNORECASE),
    re.compile(r"workspace\s*="),
    re.compile(r"敏感路径"),
    re.compile(r"拦截阈|审批阈|block_at|review_at", re.IGNORECASE),
    re.compile(r"\bCIDR\b|内网网段", re.IGNORECASE),
)
_POLICY_SCORE = 0.85  # critical → 出口拦截不回传

# ── tool_list_leak:枚举可调工具清单 ────────────────────────────────────────
# 框架词:自陈"可调用/可用/能调用的工具""工具清单/列表""available/my tools"。
_TOOL_FRAME = re.compile(
    r"(?:可调用|可用|能调用|可以使用|我能调用)的?工具"
    r"|工具(?:列表|清单|有)"
    r"|(?:available|my|the)\s+tools?"
    r"|tools?\s+(?:i\s+can|available|list)",
    re.IGNORECASE,
)
# 点分工具标识(file.read / shell.exec / external.send …);要 ≥2 个不同,排除偶发单个。
_TOOL_TOKEN = re.compile(r"\b[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\b")
_TOOL_SCORE = 0.65  # high → 出口标注待人工复核


def _severity(score: float) -> str:
    if score >= 0.8:
        return "critical"
    if score >= 0.6:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"


@capability("detector", "disclosure_egress")
class DisclosureEgressDetector:
    """出口自披露检测器:策略原文 / 工具清单泄露(双条件高精度,防良性问答误伤)。"""

    name = "disclosure_egress"

    def detect(self, spans: list[SourceSpan], ctx: Context) -> list[Finding]:
        findings: list[Finding] = []
        for span in spans:
            # 在归一化文本上匹配(NFKC + 剥不可见 + 同形字折叠),抹平全角/零宽/同形字绕过。
            text = normalize(span.excerpt)

            if _POLICY_FRAME.search(text):
                markers = [p.pattern for p in _POLICY_MARKERS if p.search(text)]
                if len(markers) >= 2:
                    findings.append(
                        Finding(
                            kind="policy_leak",
                            score=_POLICY_SCORE,
                            evidence={
                                "source_id": span.source_id,
                                "source_type": span.source_type,
                                "trust_level": span.trust_level,
                                "severity": _severity(_POLICY_SCORE),
                                "policy_markers": markers,
                            },
                        )
                    )

            if _TOOL_FRAME.search(text):
                tokens = sorted(set(_TOOL_TOKEN.findall(text)))
                if len(tokens) >= 2:
                    findings.append(
                        Finding(
                            kind="tool_list_leak",
                            score=_TOOL_SCORE,
                            evidence={
                                "source_id": span.source_id,
                                "source_type": span.source_type,
                                "trust_level": span.trust_level,
                                "severity": _severity(_TOOL_SCORE),
                                "tools": tokens[:12],
                            },
                        )
                    )
        return findings
