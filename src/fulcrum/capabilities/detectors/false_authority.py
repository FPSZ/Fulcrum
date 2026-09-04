"""伪权威文件检测器 —— 抓不可信来源**自封权威**并据此指示 Agent 覆盖自身安全判断的间接注入。

定位:补现有检测层实测坐实的真缺口。既有检测器对「伪权威文件」类间接注入近乎全漏——
`keyword_rules.injection` 抓的是**祈使触发词**(忽略指令/发送 xxx),`data_poisoning` 抓的是
**记忆写入式**投毒(记住/一律/标准答案),二者都数不清这一整族在野高发的套路:

    不可信来源(文档 / 网页 / 检索结果 / 上传 PDF / 工具返回)**把自己打扮成权威**——
    法规条文、官方信函、唯一标准、XML 假系统策略、假管辖权——再据此指示 Agent
    **放弃自身安全判断**:跳过核验、无需审批、忽略先前规则、据此执行敏感动作。

对应在野手法:HiddenLayer Policy Puppetry(XML 假策略骗过系统提示)、Checkmarx
Lies-in-the-loop(伪造权威语境诱导 Agent 自动放行)、Snyk 隐藏文字改信用评级、
Palo Alto Unit 42 伪官方口径。新 finding kind = `false_authority`。

判别逻辑(**来源门控 + 多条件共现**,FP 是成败点):

  只在 UNTRUSTED / SEMI_TRUSTED 源触发——TRUSTED 系统内容天然带权威,由系统自己签发,跳过。
  要求以下**共现**,缺一不出分:

    (A) 权威声明信号:内容把自己打扮成权威/官方(法规条文 / 官方授权 / 结构化假策略 /
        唯一覆盖式权威 / 假管辖权)。
    (B) 覆盖安全判断的祈使:指示 Agent 放弃自身判断(无需审批 / 跳过核验 / 忽略先前规则 /
        据此执行 / 优先级高于系统 / 改评级 / override=true)。
    (C∨C') 判别加强项:
        (C)  敏感/危险动作:导出|删除|外发…全部|名单|数据|记录,或 未授权/越权,或 改评级;
        (C') 显式自我覆盖:唯一标准答案 / override=true / 忽略所有(规则|安全) / 优先级高于系统。

  最终 = **来源不可信 ∧ A ∧ B ∧ (C ∨ C')**。这一步加强项是核心防 FP 闸:良性政务 FAQ
  常同时含 A+B(「根据《社会救助暂行办法》,符合条件者无需重复审批,可先行办理」),但既无
  危险动作也不自我覆盖 Agent 规则 → 缺 C/C' → **不触发**,把合法法规引用挡在门外。

分值/处置(仿 disclosure_egress,温和分值,不做 1.0 硬拦——FP 代价高):
  base 0.7(UNTRUSTED 满权 → 0.7 → 出口/入口闸门判 approve,交人工复核权威声明);
  半可信降权(×0.8)。仅当共现**明确危险动作**(删数据/转账/未授权/override=true 假策略)
  升至 0.85 → block。证据**只记信号族名**(authority/override/action/self_override/danger),
  绝不把敏感明文落进审计(审计自身不成泄露点)。
"""

from __future__ import annotations

import re

from ...core.domain import Context, Finding, SourceSpan, TrustLevel
from ...core.normalize import normalize
from ...core.registry import capability

# ── (A) 权威声明信号:内容把自己打扮成权威/官方 ─────────────────────────────────
_AUTHORITY: tuple[re.Pattern[str], ...] = (
    # 法规条文式:根据/依据/按照 + 《名》/ 第N条 / 修正案
    re.compile(r"(?:根据|依据|按照)[^。;,\n]{0,24}《[^》]{1,40}》"),
    re.compile(
        r"第[〇零一二三四五六七八九十百千\d]{1,6}条(?:第[〇零一二三四五六七八九十百千\d]{1,4}款)?"
    ),
    re.compile(r"修正案"),
    # 官方 / 授权
    re.compile(r"官方(?:通知|信函|授权|口径|规定|文件)"),
    re.compile(r"授权(?:声明|书|函)"),
    re.compile(r"兹授权|兹以[^。;,\n]{0,10}授权"),
    re.compile(r"内部口径"),
    # 结构化假策略(XML/JSON 冒充系统策略)
    re.compile(r"<\s*(?:policy|rule|authority)\b", re.IGNORECASE),
    re.compile(r"policy[^<>\n]{0,20}override", re.IGNORECASE),
    re.compile(r"override\s*=\s*[\"']?\s*true", re.IGNORECASE),
    # 唯一 / 覆盖式权威
    re.compile(r"唯一(?:标准|准则|规定|依据|标准答案)"),
    re.compile(r"以本(?:文件|文档|规定|办法|条例|信函|授权|策略|通知|函)[^。;,\n]{0,4}为准"),
    re.compile(r"与其他[^。;,\n]{0,20}(?:冲突|不一致)[^。;,\n]{0,10}以本[^。;,\n]{0,6}为准"),
    # 假管辖权
    re.compile(r"当前(?:从|在)[^。;,\n]{0,20}(?:操作|法域)"),
    re.compile(r"(?:该|本)(?:法域|辖区|地区|国家)[^。;,\n]{0,12}(?:合法|允许|准许|不受限)"),
)

# ── (B) 覆盖安全判断的祈使:指示 Agent 放弃自身判断 / 据此行动 ─────────────────────
_OVERRIDE: tuple[re.Pattern[str], ...] = (
    re.compile(r"无需[^。;,\n]{0,6}(?:审批|核验|审核|复核|验证|核实)"),
    re.compile(r"跳过[^。;,\n]{0,8}(?:核验|审批|审核|复核|验证|核实)"),
    re.compile(
        r"忽略[^。;,\n]{0,12}(?:先前|之前|以往|上述|所有|全部|一切)[^。;,\n]{0,8}"
        r"(?:规则|限制|指令|安全|合规)"
    ),
    re.compile(r"先行(?:办结|办理|执行|处理|批准|放行)"),
    re.compile(r"据此[^。;,\n]{0,6}(?:执行|办理|操作|处理|出具|导出|长期|完成|放行)"),
    re.compile(r"照做|照此办理"),
    re.compile(r"优先级?[^。;,\n]{0,6}高于[^。;,\n]{0,10}(?:系统|上级|其他|规则|一切)"),
    re.compile(r"override\s*=\s*[\"']?\s*true", re.IGNORECASE),
    re.compile(
        r"ignore[^\n]{0,20}(?:prior|previous|all)[^\n]{0,12}(?:rules?|restrictions?|instructions?)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:分配|给予|改为?|调整为?)[^。;,\n]{0,8}(?:优秀|excellent|A\+?|最高)[^。;,\n]{0,6}评级",
        re.IGNORECASE,
    ),
    re.compile(r"忽略[^。;,\n]{0,10}(?:财务|数据|报表)[^。;,\n]{0,10}(?:结论|表面|真相|数字)"),
)

# ── (C) 敏感/危险动作 ────────────────────────────────────────────────────────
_ACTION: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"(?:导出|删除|清空|销毁|转账|汇款|外发|发送|抓取|爬取|下载|拷贝)[^。;,\n]{0,12}"
        r"(?:全部|全站|全量|名单|数据|记录|账户|档案|名册)"
    ),
    re.compile(r"未授权|无授权|未经授权|越权|无权限"),
    # 间隙放宽到 {0,16}:改评级式常在动词与「评级」间夹一个具体等级词(Excellent/优秀/A+),
    # 原 {0,8} 太窄会被撑爆漏判(签名过拟合),放宽后「分配 Excellent 评级」也命中。
    re.compile(r"(?:分配|给予|改为?|调整为?)[^。;,\n]{0,16}(?:评级|信用等级)"),
)

# ── (C') 显式自我覆盖 Agent / 其他规则 ─────────────────────────────────────────
_SELF_OVERRIDE: tuple[re.Pattern[str], ...] = (
    re.compile(r"唯一标准答案"),
    re.compile(r"override\s*=\s*[\"']?\s*true", re.IGNORECASE),
    re.compile(
        r"忽略[^。;,\n]{0,8}(?:先前|之前|以往)?[^。;,\n]{0,4}所有[^。;,\n]{0,6}(?:规则|限制|安全|指令|合规)"
    ),
    re.compile(r"与其他[^。;,\n]{0,20}冲突[^。;,\n]{0,10}以本[^。;,\n]{0,6}为准"),
    re.compile(r"优先级?[^。;,\n]{0,6}高于[^。;,\n]{0,10}(?:系统|上级|其他|规则)"),
)

# ── 危险动作升档信号:命中即从 approve 档升到 block 档(仅明确删数据/转账/未授权/假策略 override)。
# 保守:抓取/导出这类"广动作"不升档(base 0.7→approve),避免把合法授权导出误判到硬拦。
_DANGER = re.compile(
    r"删除|清空|销毁|抹除|转账|汇款|打款"
    r"|未授权|无授权|未经授权|越权|无权限"
    r"|override\s*=\s*[\"']?\s*true",
    re.IGNORECASE,
)

_BASE = 0.7  # 权威声明 + 覆盖祈使 + 加强项 → 交人工复核(approve 档)
_DANGER_SCORE = 0.85  # 叠加明确危险动作 → 拦截(block 档)

# 来源信任级 -> 乘子(与 secret_egress 同口径):不可信满权,半可信降权;可信不触发。
_TRUST_MUL: dict[TrustLevel, float] = {
    TrustLevel.UNTRUSTED: 1.0,
    TrustLevel.SEMI_TRUSTED: 0.8,
}


def _severity(score: float) -> str:
    if score >= 0.8:
        return "critical"
    if score >= 0.6:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"


def _any(patterns: tuple[re.Pattern[str], ...], text: str) -> bool:
    return any(p.search(text) for p in patterns)


@capability("detector", "false_authority")
class FalseAuthorityDetector:
    """伪权威文件检测器:来源门控 + A∧B∧(C∨C') 共现,防良性政务法规引用误伤。

    注册名 `false_authority`,在 fulcrum.yml detectors 段启用。仅 UNTRUSTED/SEMI_TRUSTED 出分。
    """

    name = "false_authority"

    def detect(self, spans: list[SourceSpan], ctx: Context) -> list[Finding]:
        findings: list[Finding] = []
        for span in spans:
            trust_mul = _TRUST_MUL.get(span.trust_level)
            if trust_mul is None:
                # TRUSTED(系统/窗口内容):权威声明天然合法,不由本检测器判定。
                continue
            # 归一化后匹配(NFKC + 剥不可见 + 同形字折叠),抹平全角/零宽/同形字绕过。
            text = normalize(span.content)

            has_authority = _any(_AUTHORITY, text)
            has_override = _any(_OVERRIDE, text)
            if not (has_authority and has_override):
                continue  # 缺 A 或缺 B → 不出分(纯祈使 / 纯权威陈述都不误报)
            has_action = _any(_ACTION, text)
            has_self_override = _any(_SELF_OVERRIDE, text)
            if not (has_action or has_self_override):
                # A∧B 但无 C/C':良性政务 FAQ(权威 + 无需审批的信息性答复)在此挡下。
                continue

            danger = bool(_DANGER.search(text))
            score = round(min((_DANGER_SCORE if danger else _BASE) * trust_mul, 1.0), 3)
            # 证据只记命中的信号族名,绝不落敏感明文(权威声明/动作原文都不入审计)。
            signals: list[str] = ["authority", "override"]
            if has_action:
                signals.append("action")
            if has_self_override:
                signals.append("self_override")
            if danger:
                signals.append("danger")
            findings.append(
                Finding(
                    kind="false_authority",
                    score=score,
                    evidence={
                        "source_id": span.source_id,
                        "source_type": span.source_type,
                        "trust_level": span.trust_level,
                        "severity": _severity(score),
                        "signals": signals,
                    },
                )
            )
        return findings
