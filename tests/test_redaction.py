"""审计脱敏:敏感信息打码,避免审计日志自身泄露(01 §4.6/§4.8)。"""

from __future__ import annotations

import asyncio

from fulcrum.adapters.audit.memory_sink import InMemoryAuditSink
from fulcrum.adapters.model.fake_client import FakeModelClient
from fulcrum.capabilities import load_builtin_capabilities
from fulcrum.capabilities.policy.allow_all import AllowAllPolicy
from fulcrum.core.domain import AuditEventType
from fulcrum.core.pipeline import SecurityPipeline
from fulcrum.core.redaction import redact
from fulcrum.core.registry import registry


def test_redacts_id_card() -> None:
    out = redact("身份证 110101199001011234 请核对")
    assert "199001011234" not in out  # 中间被打码
    assert "110101" in out and "1234" in out  # 保留首尾便于核对
    assert "*" in out


def test_redacts_phone_and_email() -> None:
    out = redact("联系电话 13812345678,邮箱 zhangsan@gov.cn")
    assert "1234567" not in out  # 手机中段打码
    assert "138" in out and "5678" in out
    assert "zhangsan@gov.cn" not in out and "@gov.cn" in out


def test_redacts_phone_with_separators() -> None:
    # 回归:带空格/短横的手机号也须打码(此前只认 11 位连写,分隔符形式明文漏过)。
    for raw in ("138 1234 5678", "138-1234-5678"):
        out = redact(f"电话 {raw} 请保存")
        assert "1234" not in out, f"中段未打码:{out}"
        assert "138" in out and "5678" in out


def test_redacts_explicit_secret_and_long_token() -> None:
    assert "hunter2secret" not in redact("密码: hunter2secret")
    assert "AKIA1234567890ABCDEFGHIJ" not in redact("key=AKIA1234567890ABCDEFGHIJ")


def test_redacts_json_shaped_short_secret() -> None:
    # 回归:工具参数是 json.dumps 后再脱敏,key 后紧跟闭合引号曾让短密钥整条漏过。
    out = redact('{"api_key": "sk-LIVE-abcdefghij"}')
    assert "sk-LIVE-abcdefghij" not in out
    assert "***" in out


def test_redacts_legacy_15_digit_id_and_bank_card() -> None:
    out = redact("旧证 310101990307888,卡号 6228480402564890018")
    assert "310101990307888" not in out  # 15 位老身份证
    assert "6228480402564890018" not in out  # 19 位银行卡
    assert "3101" in out and "7888" in out  # 保留首尾便于核对


def test_redacts_uscc() -> None:
    # 统一社会信用代码(18 位,GB 32100)曾因 18<24 且含字母两边规则都漏 → 整条明文落库。
    out = redact("企业统一社会信用代码 91350100M000100Y43 已登记")
    assert "91350100M000100Y43" not in out  # 整条不留明文
    assert "91" in out and "0Y43" in out  # 保留首尾便于核对
    assert "************" in out  # 中段 12 位打码
    assert "已登记" in out  # 非敏感正文保留


def test_id_card_not_swallowed_by_uscc_rule() -> None:
    # 18 位纯数字身份证(末位为数字)也合 USCC 形:须先按身份证规则保留前 6 位,而非只留 2 位。
    out = redact("身份证 110101199001011234")
    assert "110101" in out  # 身份证保留前 6 位
    assert "199001011234" not in out


def test_non_uscc_token_not_over_redacted() -> None:
    # 中段非 6 位连续数字 → 不误判为信用代码,普通 18 位工单号原样保留(避免过度打码)。
    text = "工单 ABCD12CDEFGH345678 受理"
    assert redact(text) == text


def test_keeps_short_digit_runs() -> None:
    # 不过度打码:12 位订单号等 <15 位数字串原样保留(避免误伤非 PII 标识)。
    text = "订单号 123456789012 已受理"
    assert redact(text) == text


def test_redacts_aws_access_key_id() -> None:
    # AWS 密钥 ID 恰 20 字符,短于 _LONG_TOKEN 的 24 阈值;无 key= 键名时 _SECRET_KV 也不命中。
    assert "AKIAIOSFODNN7EXAMPLE" not in redact("迁移用 AKIAIOSFODNN7EXAMPLE 即可")
    assert "ASIAJ4F7XAMPLEKEY123" not in redact("临时凭据 ASIAJ4F7XAMPLEKEY123")
    out = redact("AKIAIOSFODNN7EXAMPLE")
    assert out.startswith("AKIA") and "*" in out  # 保留前缀便于核对来源


def test_redacts_pem_private_key_block() -> None:
    pem = (
        "配置:-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEA1234567890abcdef\nzzzz\n"
        "-----END RSA PRIVATE KEY----- 完毕"
    )
    out = redact(pem)
    assert "MIIEpAIBAAKCAQEA1234567890abcdef" not in out  # 私钥体不留痕
    assert "BEGIN RSA PRIVATE KEY" not in out  # 头尾结构也吞掉
    assert "配置" in out and "完毕" in out  # 非敏感正文保留


def test_redacts_jwt() -> None:
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.abc123signature456"
    out = redact(f"Authorization: Bearer {jwt}")
    assert "eyJ1c2VyIjoiYWRtaW4" not in out  # 载荷段(含 user 声明)不留痕
    assert "abc123signature456" not in out  # 签名段不留痕


def test_aws_prefix_word_not_over_redacted() -> None:
    # 普通 18 位工单号(非 AKIA 前缀、<24)不被新规则误伤。
    text = "工单 ABCD12CDEFGH345678 受理"
    assert redact(text) == text


def test_redacts_connection_uri_password() -> None:
    # 连接串 URI 内嵌口令(scheme://user:PASS@host):口令常 <24、无 key= 形,内网/IP 主机时
    # 通用规则与 _EMAIL 附带打码都抓不到 → 不专列就把生产库口令明文落库(secret_egress 标 critical)。
    for text, pw in (
        ("mysql://root:S3cr3t@db/app", "S3cr3t"),  # 裸主机名
        ("postgres://svc:Hunter2@10.1.1.2/hr", "Hunter2"),  # IP 主机
        ("mongodb+srv://admin:Pw0rd@cluster.mongodb.net/db", "Pw0rd"),  # 点分主机
        ("redis://u:longPasswordValue123456@cache:6379", "longPasswordValue123456"),
    ):
        out = redact(text)
        assert pw not in out, text
        assert "***" in out
        assert "@" in out  # 主机段保留便于排障


def test_redacts_basic_auth_header() -> None:
    # Authorization: Basic <base64(user:pass)>:base64 常 <24,短于 _LONG_TOKEN 阈值 → 整条漏过。
    out = redact("Authorization: Basic dXNlcjpwYXNz")
    assert "dXNlcjpwYXNz" not in out
    assert "Basic" in out and "***" in out


def test_benign_url_with_port_or_path_not_redacted() -> None:
    # 无凭据的普通 URL(host:port / path)不被新 URI 口令规则误打码。
    for text in (
        "见 https://example.com:8080/path?q=1",
        "文档在 https://api.gov.cn/v1/items 上",
    ):
        assert redact(text) == text, text


def test_keeps_normal_text() -> None:
    text = "你好,请帮我查询低保办件进度,谢谢。"
    assert redact(text) == text  # 无敏感量 → 原样


def test_screen_input_audit_excerpt_is_redacted() -> None:
    load_builtin_capabilities()
    pipe = SecurityPipeline(
        labeler=registry.create("labeler", "passthrough"),
        detectors=[registry.create("detector", "keyword_rules")],
        attributor=registry.create("attributor", "evidence"),
        risk_scorer=registry.create("risk_scorer", "heuristic"),
        chain_analyzer=registry.create("chain_analyzer", "noop"),
        policy=AllowAllPolicy(),
        executor=registry.create("executor", "echo"),
        tools={},
        audit=InMemoryAuditSink(),
        model_client=FakeModelClient(),
    )
    asyncio.run(pipe.screen_input("s", "我的身份证是 110101199001011234,帮我查低保"))
    events = asyncio.run(pipe.audit.events("s"))
    decided = [e for e in events if e.event_type == AuditEventType.POLICY_DECIDED]
    excerpt = decided[-1].evidence["excerpt"]
    assert "199001011234" not in excerpt  # 审计库里不存明文身份证
    assert "低保" in excerpt  # 非敏感正文保留
