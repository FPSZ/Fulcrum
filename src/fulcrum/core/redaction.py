"""敏感信息脱敏 —— 给**审计/展示用**的文本摘要打码,避免审计系统自身成为泄露点。

对应安全问题 01 §4.6/§4.8:「对审计日志做脱敏,避免审计系统自身泄露」。确定性正则,
覆盖政务场景常见敏感量:身份证号、统一社会信用代码、手机号、邮箱、显式密钥/口令、长不透明令牌。

**只用于审计/展示副本**(如判定点 evidence 的 excerpt),不改流向检测器与企业智能体的原文
——检测需要看到全文,脱敏只防"留痕环节把敏感数据落进库"。纯函数、无副作用。
"""

from __future__ import annotations

import re

# 顺序敏感:先打码结构化强标识(密钥KV/身份证/手机/长数字串/邮箱),最后兜底长令牌。
# 各替换结果含 * 或 …,会打断后续 [A-Za-z0-9_-] 连续段,故不会被长令牌规则二次命中。
# _SECRET_KV 的分隔符段允许键名后紧跟一个闭合引号("?),以覆盖 JSON 形态 "api_key":"v"
# ——工具参数恰是 json.dumps 后再脱敏,缺了这个会让 JSON 里的短密钥整条漏过。
_SECRET_KV = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"密码|口令|密钥|凭据|凭证)(\"?\s*[:=]\s*)(\"?)([^\s\"]{3,})"
)
# 统一社会信用代码(USCC,GB 32100):18 位,字符集为 0-9 与大写字母去掉 I O Z S V。
# 结构=登记管理部门+机构类别(2 位)+ 行政区划(6 位数字)+ 主体标识码(9 位)+ 校验位。
# 18<24 故 _LONG_TOKEN 抓不到、含字母故 _LONG_DIGITS 抓不到 → 不专列则整条明文漏过。
# 中段 6 位锚定为数字,显著降低把普通 18 位令牌误判为信用代码的概率。
_USCC = re.compile(
    r"(?<![0-9A-Za-z])([0-9A-HJ-NP-RTUWXY]{2}\d{6}[0-9A-HJ-NP-RTUWXY]{10})(?![0-9A-Za-z])"
)
_ID_CARD = re.compile(r"(?<![0-9])(\d{6})(\d{8})(\d{3}[0-9Xx])(?![0-9])")
# 手机号:3-4-4 分组,组间容许单个空格/短横(`138 1234 5678`、`138-1234-5678`)——
# 否则带分隔符的手机号在出口打码时整条明文漏过。重组时丢弃分隔符,统一成 138****5678。
_PHONE = re.compile(r"(?<!\d)(1[3-9]\d)[ -]?(\d{4})[ -]?(\d{4})(?!\d)")
# 15 位老身份证 / 16~19 位银行卡等长数字串(18 位新证、11 位手机各由上面专规则先处理)。
# 前置否定 [0-9*] 避免命中已被上面规则打码后残留的数字段。
_LONG_DIGITS = re.compile(r"(?<![0-9*])(\d{15,19})(?![0-9])")
# 邮箱本地段锚定长度上限(RFC 64),挡住 (\w)[\w.+-]* 在超长无 @ 串上的多项式回溯(ReDoS)。
_EMAIL = re.compile(r"(\w)[\w.+-]{0,63}(@[\w.-]{1,255}\.\w{2,24})")
_LONG_TOKEN = re.compile(r"(?<![A-Za-z0-9_\-])([A-Za-z0-9_\-]{24,})(?![A-Za-z0-9_\-])")
# PEM 私钥/证书块:整块吞掉(多行)。须最先处理,否则块体被其它规则零散打码、头尾结构仍留痕。
_PEM_BLOCK = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
# AWS 访问密钥 ID:前缀 + 16 位,合计 20 字符。**短于 _LONG_TOKEN 的 24 阈值**,且无 key= 键名
# 时 _SECRET_KV 也不命中 → 不专列就整条明文落库。前缀有判别力(AKIA/ASIA/AROA/AIDA…),低误报。
_AWS_KEY = re.compile(
    r"(?<![A-Za-z0-9])((?:AKIA|ASIA|AROA|AIDA|ABIA|ACCA)[A-Z0-9]{16})(?![A-Za-z0-9])"
)
# JWT:三段 base64url 以 . 分隔,前两段以 eyJ 开头。各段常 <24 且被 . 截断,_LONG_TOKEN 抓不全 →
# 作为整体识别。锚定前两段的 eyJ 头,避免误伤普通点分串。
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}")
# HTTP 授权头凭据值:Bearer/Basic 之后的令牌。Basic 的 base64(编码 user:pass,常 <24)与短
# Bearer 令牌都低于 _LONG_TOKEN 的 24 阈值、又无 key= 形 → 不专列就连 user:pass 一起明文落库。
# 保留方案名(Bearer/Basic)便于排障,值整体打码。
_AUTH_HDR = re.compile(r"(?i)\b(authorization\s*:\s*(?:bearer|basic)\s+)([A-Za-z0-9._~+/\-]{4,}=*)")
# 连接串 URI 内嵌口令 scheme://user:PASS@host。口令常 <24、又无 key= 形,通用规则均抓不到;
# 内网/IP 主机时连 _EMAIL 的附带打码都蹭不上 → 不专列就把生产库口令明文落进审计,正是
# secret_egress 标 critical 的同一串。仅打码口令段,保留 scheme://user@host 便于排障。
# 口令段排除 `:/@` 以不越过 host:port;含 `@` 的未转义口令(RFC 应 %40)非常态,不强求。
_URI_CRED = re.compile(r"([a-z][a-z0-9+.\-]*://[^\s:/@]+:)([^\s:/@]+)(@)", re.IGNORECASE)


def _mask_uscc(m: re.Match[str]) -> str:
    """信用代码保留前 2 位(登记部门+机构类别)与末 4 位,中段打码。"""
    code = m.group(1)
    return f"{code[:2]}{'*' * 12}{code[-4:]}"


def _mask_digits(m: re.Match[str]) -> str:
    """长数字串保留首尾各 4 位、中间打码(便于核对又不泄露完整号码)。"""
    digits = m.group(1)
    return f"{digits[:4]}{'*' * (len(digits) - 8)}{digits[-4:]}"


def redact(text: str) -> str:
    """对文本做敏感信息打码,返回脱敏后的副本(原值不可从结果恢复)。"""
    if not text:
        return text
    # PEM 私钥整块先吞:置于所有规则之前,避免块体被零散打码后头尾结构仍留痕。
    text = _PEM_BLOCK.sub("[私钥已脱敏]", text)
    # 授权头凭据值 / 连接串 URI 口令:置于通用规则之前,确保短凭据(<24)也被整段打码,
    # 而非被 _EMAIL/_LONG_TOKEN 部分命中后残留首字符或整条漏过。
    text = _AUTH_HDR.sub(lambda m: f"{m.group(1)}***", text)
    text = _URI_CRED.sub(lambda m: f"{m.group(1)}***{m.group(3)}", text)
    text = _SECRET_KV.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}***", text)
    text = _ID_CARD.sub(lambda m: f"{m.group(1)}{'*' * 8}{m.group(3)}", text)
    # USCC 置于身份证之后:18 位纯数字身份证(末位为数字)也合 USCC 形,先按身份证打码
    # (保留前 6 位便于核对);真·信用代码含字母、断不开 17 位连续数字,身份证规则抓不到,
    # 留给本规则。两者均在长数字串规则之前,避免内嵌数字段被部分命中留残段。
    text = _USCC.sub(_mask_uscc, text)
    text = _PHONE.sub(lambda m: f"{m.group(1)}****{m.group(3)}", text)
    text = _LONG_DIGITS.sub(_mask_digits, text)
    text = _EMAIL.sub(lambda m: f"{m.group(1)}***{m.group(2)}", text)
    # 凭据令牌:AWS 密钥 ID(短于通用阈值)与 JWT(分段被点截断)单列,置于通用长令牌规则之前。
    # 保留前缀便于核对来源(AKIA…/eyJ…),其余打码;插入的 … 会打断后续连续段,不被通用规则二次命中。
    text = _AWS_KEY.sub(lambda m: f"{m.group(1)[:4]}…***", text)
    text = _JWT.sub("eyJ…***", text)
    text = _LONG_TOKEN.sub(lambda m: f"{m.group(1)[:4]}…***", text)
    return text
