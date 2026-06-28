"""SecretEgressDetector —— 出口凭据/系统提示泄露检测(对应 OWASP LLM02/LLM07,目标①④)。

定位:补现有检测层的**出口盲区**。`keyword_rules` 的 `pii_leak` 数的是身份证/手机/邮箱这类
**个人**敏感量;`sensitive_file` 只识"提到凭据"的措辞。二者都抓不住**基础设施级活密钥**在回复里
被原样吐出——含口令的数据库连接串、云厂商 API 密钥、私钥块、`Authorization: Bearer` 令牌——
也抓不住智能体被诱导**复述自己的系统提示词**(LLM07 系统提示泄露)。本检测器专补这两类:

    credential_egress   回复/输入夹带**带凭据的连接串 / 云厂商·AI 厂商密钥 / 私钥块 /
                        Authorization 头令牌 / 裸 JWT 访问令牌**
    system_prompt_leak  自陈式系统提示披露("以下是我的系统提示词…")+ 提示模板边界标记

与既有能力互补、不重叠:
- 与 `core/redaction`(给审计副本打码)正交——那是**脱敏留痕**,本检测器是**拦投递**:
  出口闸门据此把"把生产库口令吐给用户"的回复直接拦下,不让它到达终端。
- 与 `keyword_rules.injection` 不重叠——后者抓**输入里**索取提示词的祈使句(reveal/泄露 prompt),
  本检测器抓**输出里**智能体真的开始**披露**(here is my system prompt / 我的系统提示词是)。

来源信任分流(复用与 keyword_rules 同口径的乘子):用户**自己**粘一段含口令的连接串求助
(TRUSTED→降权,不在入口硬拦);而智能体在回复里(ASSISTANT/UNTRUSTED)吐同样的串→满权→拦截。
同一特征、按来源定severity,既不误伤求助,也不放过泄露。

确定性、可解释、低延迟。**证据不落明文密钥**——finding evidence 只记命中的子类标签,
不把捕获到的密钥/口令写进审计(否则审计自身成泄露点,违背 01 §4.6)。
"""

from __future__ import annotations

import base64
import json
import re

from ...core.domain import Context, Finding, SourceSpan, TrustLevel
from ...core.registry import capability

# ── credential_egress:带凭据的连接串 / 云厂商密钥 / 私钥 / 授权头 ──────────────
# 连接串 URI 内嵌口令:scheme://user:pass@host。scheme 限定为会承载凭据的已知协议,
# 作精度锚点;group(1)=口令段,供占位词过滤(教学示例 user:password@ 不算泄露)。
_URI_CRED = re.compile(
    r"(?i)\b(?:mysql|mariadb|postgres(?:ql)?|mongodb(?:\+srv)?|redis|rediss|amqps?|"
    r"sftp|ftp|mssql|oracle|clickhouse|cockroachdb|ldaps?|jdbc:[a-z0-9]+|https?)://"
    r"[^\s:/@]+:([^\s:/@]{1,})@[^\s/]+"
)
# ADO.NET / JDBC / ODBC 键值式连接串:必须同时含 主机类键 与 password 键(才是真连接串,
# 而非孤立的 password= 提及——后者归 keyword_rules.pii_leak)。group(1)=口令段。
_ADO_CRED = re.compile(
    r"(?i)(?:server|data source|host|initial catalog|database|uid|user id)\s*=\s*[^\s;]+;"
    r"(?:[^;]*;)*?\s*(?:password|pwd)\s*=\s*([^\s;]{1,})"
)
# PEM 私钥块:出现即活私钥外泄。
_PEM = re.compile(r"-----BEGIN (?:[A-Z0-9 ]*)PRIVATE KEY-----")
# HTTP 授权头携带 Bearer/Basic 令牌实值。
_AUTH_HDR = re.compile(r"(?i)\bauthorization\s*:\s*(?:bearer|basic)\s+[A-Za-z0-9._\-+/=]{8,}")
# 高熵前缀型云厂商/AI 厂商/服务密钥(前缀锚定,近零误报):AWS / Google / GitHub / Slack /
# Stripe / OpenAI / Anthropic / GitLab / HuggingFace。本系统本身是代理上游 OpenAI·Anthropic 的
# AI 网关——这两家的密钥正是它持有/转发的凭据,却原本一个都不识别,补上是出口闸门的应有之义。
_PROVIDER = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"(?:AKIA|ASIA)[A-Z0-9]{16}"  # AWS access key id
    r"|AIza[0-9A-Za-z_\-]{35}"  # Google API key
    r"|gh[pousr]_[A-Za-z0-9]{36,}"  # GitHub token
    r"|github_pat_[A-Za-z0-9_]{60,}"  # GitHub 细粒度 PAT
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"  # Slack token
    r"|sk_live_[A-Za-z0-9]{16,}"  # Stripe live secret
    r"|sk-proj-[A-Za-z0-9_-]{20,}"  # OpenAI 项目密钥
    r"|sk-ant-[A-Za-z0-9_-]{24,}"  # Anthropic 密钥(本网关上游)
    r"|sk-[A-Za-z0-9]{32,}"  # OpenAI 传统密钥
    r"|glpat-[A-Za-z0-9_-]{20,}"  # GitLab 个人访问令牌
    r"|hf_[A-Za-z0-9]{34,}"  # HuggingFace 令牌
    r"|ya29\.[A-Za-z0-9_\-]{20,}"  # Google OAuth 访问令牌
    r")"
)
# 裸 JWT 访问令牌:无 Authorization 头包裹时 _AUTH_HDR 抓不到,而 JWT 本身即可直接当 Bearer 用。
# 结构 = header.payload.signature 三段 base64url,与签发方无关(通用能力,非某家签名)。靠**解码
# 校验**保精度:第一段须能 base64url 解成含 "alg" 字段的 JOSE 头 JSON(JWS 强制字段);随机点分串 /
# data-uri / 版本号 / 三段单词一律解不出合法头 → 近零误报。
_JWT = re.compile(
    r"(?<![A-Za-z0-9_/+\-])(eyJ[A-Za-z0-9_-]{8,})\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}"
    r"(?![A-Za-z0-9_/+\-])"
)

# ── system_prompt_leak:自陈式披露 + 提示模板边界标记 ──────────────────────────
# 自陈披露:智能体真的开始交代自己的系统提示/指令(而非输入里索取的祈使句)。
_SP_PHRASE = re.compile(
    r"(?i)(?:here (?:is|are) (?:my|the) (?:full |complete |system )*(?:system )?"
    r"(?:prompt|instructions)|my system prompt is"
    r"|我的(?:系统)?(?:提示词?|指令|设定|配置)(?:是|为|如下|包括|有)"
    r"|以下是(?:我(?:的|收到的)?)?(?:系统)?(?:提示词?|指令|设定))"
)
# 模板边界标记(刻意避开 keyword_rules.injection 已覆盖的 <|im_start|>/[INST]/</system>)。
_SP_MARK = re.compile(
    r"(?i)(?:<<SYS>>|#{2,}\s*system\s*prompt|begin\s+system\s+prompt"
    r"|[【\[]\s*系统提示词?\s*[】\]])"
)

# 占位口令:教学/模板示例里的假口令,命中不算凭据外泄(降误报)。
_PLACEHOLDER_PW: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "pass",
        "secret",
        "yourpassword",
        "examplepassword",
        "changeme",
        "placeholder",
        "xxx",
        "test",
        "none",
        "null",
        "123456",
        "mypassword",
        "dbpassword",
    }
)
_PW_YOUR = re.compile(r"your.*(?:password|pass|pwd|secret|token|key|credential)")
_PW_MASK = re.compile(r"[x*.]{2,}")

# credential_egress(critical)与 system_prompt_leak(high)两类的固有严重度基准。
_CRED_BASE = 0.9
_SP_BASE = 0.7

# 来源信任级 -> 乘子(与 keyword_rules 同口径):不可信来源吐密钥满权,用户自陈降权。
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


def _is_placeholder_pw(pw: str) -> bool:
    """连接串里的口令段是否只是占位/示例(教学文档,不算真泄露)。"""
    s = re.sub(r"[\s_-]", "", pw.strip().strip("<>[]{}()")).lower()
    if not s or s in _PLACEHOLDER_PW:
        return True
    if _PW_YOUR.fullmatch(s):
        return True
    return bool(_PW_MASK.fullmatch(s))


def _is_jwt(text: str) -> bool:
    """文本里是否含一个**结构与解码都成立**的 JWT(第一段 base64url 解出含 alg 的 JOSE 头)。"""
    for m in _JWT.finditer(text):
        seg = m.group(1)
        try:
            header = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
        except (ValueError, TypeError):
            continue
        if isinstance(header, dict) and "alg" in header:
            return True
    return False


def _credential_labels(text: str) -> list[str]:
    """返回命中的凭据外泄子类标签(去重、固定顺序);占位口令的连接串不计入。"""
    labels: list[str] = []
    if any(not _is_placeholder_pw(m.group(1)) for m in _URI_CRED.finditer(text)):
        labels.append("connection_uri")
    if any(not _is_placeholder_pw(m.group(1)) for m in _ADO_CRED.finditer(text)):
        labels.append("connection_string")
    if _PEM.search(text):
        labels.append("private_key")
    if _AUTH_HDR.search(text):
        labels.append("authorization_header")
    if _PROVIDER.search(text):
        labels.append("provider_secret")
    if _is_jwt(text):
        labels.append("jwt")
    return labels


def _system_prompt_labels(text: str) -> list[str]:
    labels: list[str] = []
    if _SP_PHRASE.search(text):
        labels.append("self_disclosure")
    if _SP_MARK.search(text):
        labels.append("template_marker")
    return labels


@capability("detector", "secret_egress")
class SecretEgressDetector:
    """出口凭据/系统提示泄露检测器。注册名 `secret_egress`,在 fulcrum.yml detectors 启用。"""

    name = "secret_egress"

    def detect(self, spans: list[SourceSpan], ctx: Context) -> list[Finding]:
        findings: list[Finding] = []
        for span in spans:
            text = span.excerpt
            trust_mul = _TRUST_MUL.get(span.trust_level, 1.0)
            for kind, base, labels in (
                ("credential_egress", _CRED_BASE, _credential_labels(text)),
                ("system_prompt_leak", _SP_BASE, _system_prompt_labels(text)),
            ):
                if not labels:
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
                            # 只记命中的子类标签,绝不把捕获到的密钥/口令写进证据(审计不成泄露点)。
                            "matched_kinds": labels,
                        },
                    )
                )
        return findings
