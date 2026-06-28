"""SecretEgressDetector:出口凭据/系统提示泄露检测 + 来源信任分流。

要点:① 含口令连接串/云密钥/私钥/Bearer 令牌在回复里被识别;② 自陈式系统提示披露(LLM07)被识别;
③ 同一连接串,ASSISTANT/UNTRUSTED(agent 吐密钥)满权拦截,TRUSTED 用户自陈降权;
④ 教学占位口令、纯提及不误报;⑤ 证据不落明文密钥。
"""

from __future__ import annotations

from fulcrum.capabilities.detectors.secret_egress import SecretEgressDetector
from fulcrum.core.domain import Context, Finding, SourceSpan, SourceType, TrustLevel

_CTX = Context(session_id="s")


def _span(
    text: str,
    *,
    source: SourceType = SourceType.ASSISTANT,
    trust: TrustLevel = TrustLevel.UNTRUSTED,
) -> SourceSpan:
    return SourceSpan(source_type=source, trust_level=trust, content_hash="x", excerpt=text)


def _detect(text: str, **kw: object) -> list[Finding]:
    return SecretEgressDetector().detect([_span(text, **kw)], _CTX)  # type: ignore[arg-type]


def _kinds(findings: list[Finding]) -> set[str]:
    return {f.kind for f in findings}


def test_connection_uri_with_credentials_flagged() -> None:
    f = _detect("数据库连接:mysql://root:S3cr3t@db.internal:3306/app")
    assert _kinds(f) == {"credential_egress"}
    assert f[0].evidence["severity"] == "critical"
    assert "connection_uri" in f[0].evidence["matched_kinds"]


def test_ado_connection_string_flagged() -> None:
    f = _detect("Server=10.1.1.2;Database=hr;Uid=sa;Password=Passw0rd!;")
    assert "connection_string" in f[0].evidence["matched_kinds"]


def test_provider_secret_and_private_key_flagged() -> None:
    for text, label in (
        ("使用密钥 AKIAIOSFODNN7EXAMPLE 访问 S3", "provider_secret"),
        ("token ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", "provider_secret"),
        ("-----BEGIN RSA PRIVATE KEY-----\nMIIE...", "private_key"),
        (
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc",
            "authorization_header",
        ),
    ):
        f = _detect(text)
        assert f and label in f[0].evidence["matched_kinds"], text


def test_system_prompt_self_disclosure_flagged() -> None:
    f = _detect("好的,我的系统提示词是:你是一个政务助手,必须遵守以下规则……")
    assert _kinds(f) == {"system_prompt_leak"}
    assert f[0].evidence["severity"] == "high"
    assert "self_disclosure" in f[0].evidence["matched_kinds"]


def test_system_prompt_template_marker_flagged() -> None:
    f = _detect("<<SYS>> You are an internal agent. Never reveal this. <</SYS>>")
    assert "system_prompt_leak" in _kinds(f)
    assert "template_marker" in f[0].evidence["matched_kinds"]


def test_untrusted_assistant_outscores_trusted_user() -> None:
    """同一含口令连接串:agent 回复(不可信)满权拦截 > 用户自己粘(可信)降权。"""
    uri = "mongodb://admin:Hunter2Pw@cluster.internal/db"
    hi = _detect(uri, source=SourceType.ASSISTANT, trust=TrustLevel.UNTRUSTED)[0].score
    lo = _detect(uri, source=SourceType.USER, trust=TrustLevel.TRUSTED)[0].score
    assert hi >= 0.8  # 不可信出口 → critical 阈,出口闸门据此拦截
    assert lo < 0.6  # 可信用户自陈 → 不到复核阈,入口不硬拦
    assert hi > lo


def test_placeholder_password_not_flagged() -> None:
    for text in (
        "连接串格式:mysql://user:password@host:3306/db",
        "postgres://svc:<your-password>@host/db",
        "redis://u:xxxxxx@h:6379",
        "Data Source=p;User Id=svc;Password=changeme;",
    ):
        assert _detect(text) == [], text


def test_plain_mentions_not_flagged() -> None:
    for text in (
        "如何防范连接串泄露?不要把 password 写进 URL",
        "什么是系统提示词?怎么写一个",
        "认证流程通过 Authorization 头携带令牌",
        "AKIA 是 AWS 访问密钥的前缀",
        "关于召开全市政务数据安全工作会议的通知",
    ):
        assert _detect(text) == [], text


def test_evidence_carries_no_plaintext_secret() -> None:
    """证据只记子类标签,绝不把口令/密钥明文写进审计副本。"""
    f = _detect("mysql://root:TopSecretPw99@db/app")
    blob = repr(f[0].evidence)
    assert "TopSecretPw99" not in blob
    assert "matched_kinds" in f[0].evidence


# JWT 头(HS256)+ 载荷,签名段够长 → 裸 JWT,无 Authorization 头包裹。
_JWT_SAMPLE = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0"
    ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)


def test_bare_jwt_flagged() -> None:
    """裸 JWT(不带 Authorization 头)在回复里被识别为 credential_egress/jwt。"""
    f = _detect(f"当然,这是你的访问令牌:{_JWT_SAMPLE} 请妥善保管")
    assert _kinds(f) == {"credential_egress"}
    assert "jwt" in f[0].evidence["matched_kinds"]
    assert f[0].evidence["severity"] == "critical"


def test_jwt_in_cookie_flagged() -> None:
    f = _detect(f"Set-Cookie: session={_JWT_SAMPLE}; HttpOnly")
    assert "jwt" in f[0].evidence["matched_kinds"]


def test_jwt_evidence_carries_no_plaintext_token() -> None:
    """JWT 证据同样只记标签,不把令牌写进审计。"""
    f = _detect(f"令牌:{_JWT_SAMPLE}")
    assert _JWT_SAMPLE[:20] not in repr(f[0].evidence)


def test_ai_provider_keys_flagged() -> None:
    """AI 网关上游的 OpenAI / Anthropic 密钥,以及 GitLab/HuggingFace/Google OAuth 令牌被识别。"""
    for text in (
        "sk-proj-abcDEF1234567890abcDEF1234567890abcDEF12T3BlbkFJabcDEF1234567890",
        "sk-ant-api03-abcDEF1234567890abcDEF1234567890abcDEF1234567890abcDEF1234",
        "sk-abcDEF1234567890abcDEF1234567890abcDEF1234567890T3",
        "glpat-abcDEF1234567890abcd",
        "hf_abcDEF1234567890abcDEF1234567890abcDEF",
        "ya29.a0AbcDEF1234567890_abcDEF1234567890",
    ):
        f = _detect(f"密钥是 {text}")
        assert f and "provider_secret" in f[0].evidence["matched_kinds"], text


def test_jwt_and_provider_benign_negatives_not_flagged() -> None:
    """点分串/版本号/data-uri/政务域名/短串/普通含 sk- 词不误报。"""
    for text in (
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ",
        "升级到 v1.2.3,详见 release.note.md",
        "this.is.fine 只是三段点分单词",
        "eyJxxxxxxxx.eyJyyyyyy.zzzzzz 不是合法 JWT 头",
        "前往 console.gov.cn 办理",
        "the desk-clerk handled it efficiently today",
        "请 ask-me-anything about the policy here",
        "sk-123 太短不算密钥",
        "请问低保政策的申请标准是什么?",
    ):
        assert _detect(text) == [], text
