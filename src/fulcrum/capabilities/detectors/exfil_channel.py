"""ExfilChannelDetector —— 出站外泄**信道**识别(对应 OWASP LLM02 数据外泄,目标①④)。

补出口盲区的**信道维度**。既有检测各管一段、却都漏掉「外泄目的地本身」:
- `keyword_rules.markup_exfil` 抓 markdown 图片/链接「渲染即外联」(URL 查询串夹带编码数据);
- `keyword_rules.exfiltration` 抓「发送/上传到 http」这类**带措辞**的外发;
- `toolguard/argrisk` 在**工具参数**层做 SSRF —— 但只拦内网 IP / 非白名单,公网外泄汇点放行。

本检测器专补:**回复或不可信内容里直接出现的外泄信道目的地**——无需外发措辞、无需长载荷、
目的地是公网(SSRF 不触发)。三类:

    oob_exfil_sink     带外交互/即用抓包基础设施(interactsh / Burp Collaborator / oast /
                       dnslog / webhook.site / requestbin / pipedream / ngrok 隧道…)。这些域名
                       **专为带外回显/抓包而生**,政务·企业智能体语境里近乎零正常用途,出现即
                       强外泄信号 → critical。族名册同 `secret_egress` 高熵前缀册,近零误报。
    messaging_webhook  即时通讯入站 webhook(Discord/Slack/Telegram/Teams/飞书/钉钉)**完整带令牌**
                       的投递 URL —— 本身即一条对外频道的活投递凭据,被诱导把数据 POST 过去是
                       智能体外泄经典手法 → high(待复核;双用,靠来源信任分流降误伤、且必须含令牌
                       段才命中,裸提及 discord.com 不算)。
    dns_tunnel         DNS 隧道形:某主机**最左标签**是异常长(≥40)且高熵的编码块——把数据塞进
                       子域名标签靠一次解析带出。**熵闸(≥4.2 bit/char)天然排除 hex 散列**
                       (md5/sha1/sha256 熵≈4.0)、CDN 父域白名单排除随机子域常态 → high。

精度优先,**证据不落**完整子域/令牌明文(只记信道族 + 元信息),审计不成泄露点(同 01 §4.6)。
来源信任分流复用 `secret_egress` 同口径乘子:用户自粘求助降权、agent 出口满权。确定性、低延迟。
"""

from __future__ import annotations

import math
import re
from collections import Counter

from ...core.domain import Context, Finding, SourceSpan, TrustLevel
from ...core.registry import capability

# ── oob_exfil_sink:带外交互/即用抓包基础设施域名册 ──────────────────────────────
# 这些注册域**专门**用于带外回显、DNS/HTTP 抓包或临时隧道,正常业务回复里不会出现。
_OOB_DOMAINS = (
    r"oast\.(?:fun|site|live|online|pro|me)",  # projectdiscovery interactsh 公共实例
    r"interact\.sh",
    r"burpcollaborator\.net",
    r"oastify\.com",  # Burp 默认 Collaborator
    r"dnslog\.(?:cn|link|pw)",
    r"requestrepo\.com",
    r"canarytokens\.(?:com|org)",
    r"webhook\.site",
    r"requestbin\.(?:com|net)",
    r"requestcatcher\.com",
    r"pipedream\.net",
    r"beeceptor\.com",
    r"hookbin\.com",
    r"mockbin\.(?:io|org)",
    r"ngrok\.(?:io|app)",
    r"ngrok-free\.app",
    r"trycloudflare\.com",
    r"loca\.lt",
    r"serveo\.net",
    r"localtunnel\.me",
    r"pagekite\.me",
)
# (可选子域.)+ 汇点域,且汇点域须为**registrable 后缀**(尾随 `(?![\w.-])` 杜绝
# `oast.fun.evil.com` 这种把汇点名当子标签的伪命中)。group(1)=命中的汇点族(供证据)。
_OOB_RE = re.compile(
    r"(?<![\w.-])(?:[a-z0-9-]+\.)*(" + "|".join(_OOB_DOMAINS) + r")(?![\w.-])",
    re.IGNORECASE,
)

# ── messaging_webhook:即时通讯入站 webhook(必须含令牌段,裸域名不算)──────────────
_WEBHOOK_RES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "discord",
        re.compile(
            r"https?://(?:[a-z0-9-]+\.)?discord(?:app)?\.com/api/(?:v\d+/)?webhooks/"
            r"\d{17,20}/[\w-]{60,}",
            re.IGNORECASE,
        ),
    ),
    (
        "slack",
        re.compile(
            r"https?://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}",
            re.IGNORECASE,
        ),
    ),
    (
        "telegram",
        re.compile(r"https?://api\.telegram\.org/bot\d{6,}:[A-Za-z0-9_-]{30,}/", re.IGNORECASE),
    ),
    (
        "teams",
        re.compile(r"https?://[a-z0-9-]+\.webhook\.office\.com/webhookb2/[\w-]{8,}", re.IGNORECASE),
    ),
    (
        "feishu",
        re.compile(
            r"https?://open\.(?:feishu\.cn|larksuite\.com)/open-apis/bot/v\d/hook/[\w-]{16,}",
            re.IGNORECASE,
        ),
    ),
    (
        "dingtalk",
        re.compile(
            r"https?://oapi\.dingtalk\.com/robot/send\?access_token=[\w-]{32,}", re.IGNORECASE
        ),
    ),
)

# ── dns_tunnel:最左长高熵标签 + registrable 父域 ────────────────────────────────
# 最左标签 ≥40 字符([a-z0-9-]),其后接 (子域.)* registrable.tld。熵在 _dns_tunnel_parent 里判。
_HOST_RE = re.compile(
    r"(?<![\w.-])([a-z0-9-]{40,})\.((?:[a-z0-9-]+\.)*[a-z0-9-]+\.[a-z]{2,})(?![\w.-])",
    re.IGNORECASE,
)
# CDN/对象存储等**天然带长随机子域**的父域:此处排除,避免把哈希分发主机误判成隧道。
_CDN_PARENTS = (
    "amazonaws.com",
    "cloudfront.net",
    "azureedge.net",
    "azure.com",
    "googleusercontent.com",
    "googleapis.com",
    "cloudflare.net",
    "cloudflarestorage.com",
    "fastly.net",
    "fastlylb.net",
    "akamai.net",
    "akamaiedge.net",
    "akamaihd.net",
    "b-cdn.net",
    "cdn77.org",
    "cachefly.net",
    "blob.core.windows.net",
)
_DNS_ENTROPY_MIN = 4.2  # bit/char:hex 散列(md5/sha1/sha256)≈4.0 在闸下,base32+ 编码在闸上


def _shannon(s: str) -> float:
    n = len(s)
    if n == 0:
        return 0.0
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _oob_families(text: str) -> list[str]:
    """命中的带外汇点族(去重、固定顺序);不记完整子域(子域可能就是被编码的数据)。"""
    fams: list[str] = []
    for m in _OOB_RE.finditer(text):
        fam = m.group(1).lower()
        if fam not in fams:
            fams.append(fam)
    return fams


def _webhook_platforms(text: str) -> list[str]:
    """命中的即时通讯 webhook 平台名(去重、固定顺序);不记令牌段。"""
    plats: list[str] = []
    for name, pat in _WEBHOOK_RES:
        if pat.search(text) and name not in plats:
            plats.append(name)
    return plats


def _dns_tunnel_parent(text: str) -> str | None:
    """有则返回隧道主机的 registrable 父域(不返回编码标签本身);否则 None。"""
    for m in _HOST_RE.finditer(text):
        label, parent = m.group(1).lower(), m.group(2).lower()
        if any(parent == d or parent.endswith("." + d) for d in _CDN_PARENTS):
            continue
        if _shannon(label) >= _DNS_ENTROPY_MIN:
            return parent
    return None


# 三类固有严重度基准。
_OOB_BASE = 0.9  # critical:专用带外基础设施,出现即强信号
_WEBHOOK_BASE = 0.7  # high:活投递凭据,待复核
_DNS_BASE = 0.7  # high:隧道形,待复核

# 来源信任级 -> 乘子(与 secret_egress/keyword_rules 同口径)。
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


@capability("detector", "exfil_channel")
class ExfilChannelDetector:
    """出站外泄信道检测器。注册名 `exfil_channel`,在 fulcrum.yml detectors 启用。"""

    name = "exfil_channel"

    def detect(self, spans: list[SourceSpan], ctx: Context) -> list[Finding]:
        findings: list[Finding] = []
        for span in spans:
            text = span.excerpt
            trust_mul = _TRUST_MUL.get(span.trust_level, 1.0)

            oob = _oob_families(text)
            webhooks = _webhook_platforms(text)
            dns_parent = _dns_tunnel_parent(text)

            for kind, base, detail in (
                ("oob_exfil_sink", _OOB_BASE, {"sink_families": oob} if oob else None),
                (
                    "messaging_webhook",
                    _WEBHOOK_BASE,
                    {"platforms": webhooks} if webhooks else None,
                ),
                (
                    "dns_tunnel",
                    _DNS_BASE,
                    {"parent_domain": dns_parent} if dns_parent else None,
                ),
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
                            # 只记信道族/平台/父域,绝不把完整子域/令牌写进证据(审计不成泄露点)。
                            **detail,
                        },
                    )
                )
        return findings
