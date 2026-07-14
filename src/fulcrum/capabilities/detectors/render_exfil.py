"""RenderExfilDetector —— 「渲染即外泄」数据槽外泄模板 + CSS/样式隐藏注入信道识别。

补间接注入(indirect_injection)桶三条实测漏判代表的一类缺口。既有
`keyword_rules.markup_exfil` 抓「渲染即外联」,但要求外链查询串取值是 **24+ 位编码块**或
**现成 PII 明文**(18 位身份证/11 位手机号)。攻击者只要把「真实数据」推迟到 LLM **生成时**
才填(自然语言数据槽占位),或把外发指令藏进 **CSS 隐藏块**、外链查询串留空,就整体绕过。本
检测器专补这两类:

    data_slot_exfil     渲染即外联信道(markdown 图片/链接、HTML <img src>/<a href>,或「插入
                        图片/追加为链接/附上…链接/嵌入链接」这类渲染即外联祈使 + 一个外链)**且**
                        其外链目标区里点名会话/用户敏感数据类目、或留一个「把…填进来」式数据槽
                        占位符。判别 = 「markup/渲染外联信道 ∧(敏感类目引用 ∨ 填充占位符)」两
                        条件共现——普通静态图/正常查询(page=2、id=123、token=<正常值>)缺其一
                        不命中。base 0.85(untrusted→block)。

    hidden_markup_inject CSS/样式隐藏标记(font-size:0 / color:#fff / display:none / opacity:0 /
                        visibility:hidden / 屏外定位 / hidden 属性 / 零宽字符)**且**隐藏块的同
                        一元素/邻近文本里含**外发或执行祈使**(外发到外部/追加为链接/插入图片/
                        忽略之前指令/执行命令…)。判别 = 「隐藏标记 ∧ 邻近外发·执行祈使」——单纯
                        display:none 占位(无祈使无外链)不命中(良性网页藏元素很常见)。base 0.85。

来源信任分流复用 `exfil_channel`/`secret_egress` 同口径乘子(不可信满权、用户直述降权)。证据只
记信道族/类目/隐藏样式族,**绝不把敏感明文或数据槽内容落进证据**(审计不成泄露点)。确定性、
低延迟,作为第一层防线;语义兜底由 P6 judge 叠加。
"""

from __future__ import annotations

import re

from ...core.domain import Context, Finding, SourceSpan, TrustLevel
from ...core.registry import capability

# ── data_slot_exfil ────────────────────────────────────────────────────────────
# 外链 token:排除 whitespace / 括号 / 引号 / 】 / >(URL 边界),但**保留** `<`——数据槽占位
# 常写成 `?d=<把…填进来>`,`<` 是 token 一部分。
_URL_RE = re.compile(r"https?://[^\s)\]}】\"'>]+", re.IGNORECASE)

# markup 外链信道前缀:URL 紧跟在 markdown `](`、HTML `src=`/`href=` 之后(允许可选引号/`<`)。
# 分组标注信道形态(md=markdown、q=HTML 属性引号),供把"载荷区"窗口收窄到正确闭合边界——
# markdown 止于 `)`、HTML 引号属性止于闭合引号——防跨过闭括号吃后面的散文造成 FP。
_MARKUP_PRE_RE = re.compile(
    r"(?:(?P<md>\]\()|(?:src|href)\s*=)\s*(?P<q>['\"])?\s*<?\s*$", re.IGNORECASE
)

# 渲染即外联祈使(信道的另一形态:无 markdown 语法但「插入图片/追加为链接/嵌入链接…」+ 外链)。
_RENDER_INSTR_RE = re.compile(
    r"(?:插入|嵌入|附上|附加|追加|加上|放上|贴上|展示|显示)[^。\n]{0,12}"
    r"(?:图片|图像|这张图|logo|链接|超链接|引用链接|url|网址)"
    r"|追加为(?:引用)?链接"
    r"|(?:insert|embed|append|attach|include|add)\b[^.\n]{0,20}"
    r"(?:image|img|picture|logo|link|url|hyperlink)",
    re.IGNORECASE,
)

# 填充占位符:尖括号数据槽 `<…把…填进来>` / `<your_token>` / `<replace…>` / `<...>` / `<xxx>`。
_PLACEHOLDER_RE = re.compile(
    r"<[^<>]{0,60}(?:填入|填进|填充|填写|替换|占位|插入|把[^<>]{0,30}填|填|"
    r"your[_ -]?\w+|replace[_ -]?\w+|placeholder|xxx+|\.\.\.)[^<>]{0,60}>",
    re.IGNORECASE,
)

# 强数据槽引用(显式点名会话/名册/凭据数据,无需量词即成立)。
_STRONG_SLOT_RE = re.compile(
    r"会话(?:内容|记录|历史|上下文)|本次会话|聊天记录|通讯录|花名册|"
    r"session\s*(?:content|history|data|context)|chat\s*history|address\s*book|roster",
    re.IGNORECASE,
)

# 量词/指代限定 + 敏感类目:量词是防 FP 的关键——普通 `token=<值>`/`session=abc` 无量词不命中,
# 攻击的「用户身份证号」「会话中的全部手机号」「all phone numbers」才命中。
_QUANT = (
    r"(?:本次|本会话|会话|用户|客户|本人|全部|所有|整个|整份|每一?位?|"
    r"the\s+user'?s?|users?'?|all|every|entire|full|whole|this\s+session'?s?)"
)
# 敏感类目(强 PII / 凭据)。刻意**不含**弱高频词 联系方式/地址/住址/contacts —— 它们是政务
# 页脚良性话术常客(「获取所有联系方式」),即便收�narrow也易在散文里凑量词误命中;真外泄模板
# 点名的是 身份证/手机号/令牌/名册/会话记录 这类强载荷,足够召回,通讯录/花名册由强槽收口。
_SENS = (
    r"(?:身份证号?|身份证|手机号码?|手机号|电话号码?|令牌|密钥|口令|密码|"
    r"凭据|凭证|cookie|phone(?:\s*numbers?)?|id[-\s]?cards?|passwords?|secrets?|tokens?|"
    r"credentials?)"
)
_QUANT_SENS_RE = re.compile(_QUANT + r"[^,。;\n]{0,8}" + _SENS, re.IGNORECASE)


# ── hidden_markup_inject ─────────────────────────────────────────────────────────
# CSS/样式隐藏标记族(family, pattern):人不可见、模型可读。
_HIDDEN_MARKERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("font_size_zero", re.compile(r"font-size\s*:\s*0(?:px|pt|em|rem)?\b", re.IGNORECASE)),
    (
        "color_white",
        re.compile(
            r"color\s*:\s*(?:#fff(?:fff)?\b|white\b|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))",
            re.IGNORECASE,
        ),
    ),
    ("display_none", re.compile(r"display\s*:\s*none", re.IGNORECASE)),
    ("visibility_hidden", re.compile(r"visibility\s*:\s*hidden", re.IGNORECASE)),
    ("opacity_zero", re.compile(r"opacity\s*:\s*0(?:\.0+)?(?![.\d])", re.IGNORECASE)),
    (
        "offscreen",
        re.compile(
            r"(?:left|top|right|bottom|text-indent|margin-left)\s*:\s*-\d{3,}", re.IGNORECASE
        ),
    ),
    ("hidden_attr", re.compile(r"<[^>]*\bhidden\b[^>]*>", re.IGNORECASE)),
    ("zero_width", re.compile("[​‌‍⁠﻿]")),
)

# 隐藏块内的外发/执行祈使:必须与隐藏标记邻近共现。裸「提交/上传材料」等良性动词不算——须
# 外发到外部(http/外部/邮箱/链接)、渲染外联、指令覆盖或命令执行语义。
_HIDDEN_INSTRUCTION_RE = re.compile(
    r"追加为(?:引用)?链接|插入(?:图片|这张图|图像)|嵌入(?:图片|链接)"
    r"|(?:外发|回传|外传|上报|发出)"
    r"|把[^。\n]{0,24}(?:发送?|外发|上传|回传|提交|转发|追加|同步)[^。\n]{0,14}"
    r"(?:https?://|外部|外网|境外|第三方|邮箱|链接|@)"
    r"|(?:发送?|上传|提交|转发|同步|post|send|upload|forward|exfiltrate)[^。\n]{0,16}"
    r"(?:https?://|外部|外网|第三方|external)"
    r"|忽略(?:之前|上述|以上|前面|正文|该|本)|无视(?:上述|之前|以上|该|本)?(?:的)?(?:指令|规则|提示)"
    r"|ignore\s+(?:the\s+)?(?:previous|above|prior|all)"
    r"|disregard\s+(?:the\s+)?(?:above|previous|all)"
    r"|执行(?:命令|脚本|以下)|运行(?:命令|脚本)|删除(?:全部|所有|整个)"
    r"|\b(?:reverse\s*shell|exfiltrate)\b",
    re.IGNORECASE,
)

# 两个 kind 固有严重度基准(untrusted→0.85≥0.8 block、semi→0.68 approve、trusted→0.468 allow)。
_DATA_SLOT_BASE = 0.85
_HIDDEN_BASE = 0.85

# 来源信任级 -> 乘子(与 exfil_channel/secret_egress/keyword_rules 同口径)。
_TRUST_MUL: dict[TrustLevel, float] = {
    TrustLevel.UNTRUSTED: 1.0,
    TrustLevel.SEMI_TRUSTED: 0.8,
    TrustLevel.TRUSTED: 0.55,
}


def _severity(score: float) -> str:
    if score >= 0.8:
        return "critical"
    if score >= 0.6:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"


def _payload_bounds(is_markdown: bool, quote: str | None) -> tuple[str, ...]:
    """外链载荷区的闭合边界字符集:窗口在此截断,不吃信道构造之后的散文(FP 根因)。

    markdown 链接止于 `)`(占位符的 `>` 在 `)` 之前,保留);HTML 引号属性止于闭合引号;
    HTML 无引号属性止于空白/`>`/`)`。
    """
    if is_markdown:
        return (")", "\n")
    if quote:
        return (quote, "\n")
    return ('"', "'", ">", " ", ")", "\n")


def _data_slot_hit(text: str) -> dict[str, str] | None:
    """渲染即外联信道 ∧ 数据槽(占位符/敏感引用)共现 → 返回信道/槽族(不落敏感明文)。

    **载荷区收窄(防 FP 根因)**:markup 支的槽引用只在"外链信道载荷区"里认——URL token +
    紧邻占位符尾,止于闭括号/闭引号,**绝不跨过 markdown `)` 去吃后面的散文**(否则政务页脚
    「[联系我们](…) 获取所有联系方式」这类良性话术会因散文里的量词+敏感词被误判)。真外泄模板
    的敏感载荷是**外链的查询值**(在 `)` 之前的 URL token 内,如 `?d=会话中的全部手机号`)。
    render 祈使支无 `)` 边界,保持 URL + 紧邻上下文窗口(判别力来自"渲染外联祈使 + 占位/强槽",
    FP 面不同)。
    """
    for m in _URL_RE.finditer(text):
        pre = text[max(0, m.start() - 40) : m.start()]
        near = text[max(0, m.start() - 64) : m.end() + 64]
        pm = _MARKUP_PRE_RE.search(pre)
        is_render = bool(_RENDER_INSTR_RE.search(near))
        if pm is None and not is_render:
            continue
        windows: list[tuple[str, str]] = []
        if pm is not None:
            tail = text[m.end() : m.end() + 64]
            cut = len(tail)
            for ch in _payload_bounds(pm.group("md") is not None, pm.group("q")):
                i = tail.find(ch)
                if i != -1:
                    cut = min(cut, i)
            windows.append(("markup_link", text[m.start() : m.end() + cut]))
        if is_render:
            windows.append(("render_instruction", text[m.start() : m.end() + 64]))
        for channel, window in windows:
            if _PLACEHOLDER_RE.search(window):
                return {"channel": channel, "slot": "placeholder"}
            if _STRONG_SLOT_RE.search(window) or _QUANT_SENS_RE.search(window):
                return {"channel": channel, "slot": "data_reference"}
    return None


def _hidden_markup_hit(text: str) -> dict[str, str] | None:
    """CSS/样式隐藏标记 ∧ 邻近外发·执行祈使共现 → 返回隐藏样式族/指令类(不落隐藏块明文)。"""
    for family, pat in _HIDDEN_MARKERS:
        for hm in pat.finditer(text):
            block = text[hm.start() : hm.end() + 220]
            if _HIDDEN_INSTRUCTION_RE.search(block):
                return {"hidden_style": family, "instruction": "exfil_or_exec"}
    return None


@capability("detector", "render_exfil")
class RenderExfilDetector:
    """渲染即外泄 / 隐藏注入信道检测器。注册名 `render_exfil`,在 fulcrum.yml detectors 启用。"""

    name = "render_exfil"

    def detect(self, spans: list[SourceSpan], ctx: Context) -> list[Finding]:
        findings: list[Finding] = []
        for span in spans:
            text = span.content
            trust_mul = _TRUST_MUL.get(span.trust_level, 1.0)

            for kind, base, detail in (
                ("data_slot_exfil", _DATA_SLOT_BASE, _data_slot_hit(text)),
                ("hidden_markup_inject", _HIDDEN_BASE, _hidden_markup_hit(text)),
            ):
                if detail is None:
                    continue
                score = round(min(base * trust_mul, 1.0), 3)
                findings.append(
                    Finding(
                        kind=kind,
                        score=score,
                        evidence={
                            "source_id": span.source_id,
                            "source_type": span.source_type,
                            "trust_level": span.trust_level,
                            "severity": _severity(score),
                            # 只记信道族/槽族/隐藏样式族,绝不把外链目标/数据槽/隐藏块明文写进证据。
                            **detail,
                        },
                    )
                )
        return findings
