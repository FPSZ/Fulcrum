"""敏感信息脱敏 —— 给**审计/展示用**的文本摘要打码,避免审计系统自身成为泄露点。

对应安全问题 01 §4.6/§4.8:「对审计日志做脱敏,避免审计系统自身泄露」。确定性正则,
覆盖政务场景常见敏感量:身份证号、手机号、邮箱、显式密钥/口令、长不透明令牌。

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
_ID_CARD = re.compile(r"(?<![0-9])(\d{6})(\d{8})(\d{3}[0-9Xx])(?![0-9])")
_PHONE = re.compile(r"(?<!\d)(1[3-9]\d)(\d{4})(\d{4})(?!\d)")
# 15 位老身份证 / 16~19 位银行卡等长数字串(18 位新证、11 位手机各由上面专规则先处理)。
# 前置否定 [0-9*] 避免命中已被上面规则打码后残留的数字段。
_LONG_DIGITS = re.compile(r"(?<![0-9*])(\d{15,19})(?![0-9])")
# 邮箱本地段锚定长度上限(RFC 64),挡住 (\w)[\w.+-]* 在超长无 @ 串上的多项式回溯(ReDoS)。
_EMAIL = re.compile(r"(\w)[\w.+-]{0,63}(@[\w.-]{1,255}\.\w{2,24})")
_LONG_TOKEN = re.compile(r"(?<![A-Za-z0-9_\-])([A-Za-z0-9_\-]{24,})(?![A-Za-z0-9_\-])")


def _mask_digits(m: re.Match[str]) -> str:
    """长数字串保留首尾各 4 位、中间打码(便于核对又不泄露完整号码)。"""
    digits = m.group(1)
    return f"{digits[:4]}{'*' * (len(digits) - 8)}{digits[-4:]}"


def redact(text: str) -> str:
    """对文本做敏感信息打码,返回脱敏后的副本(原值不可从结果恢复)。"""
    if not text:
        return text
    text = _SECRET_KV.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}***", text)
    text = _ID_CARD.sub(lambda m: f"{m.group(1)}{'*' * 8}{m.group(3)}", text)
    text = _PHONE.sub(lambda m: f"{m.group(1)}****{m.group(3)}", text)
    text = _LONG_DIGITS.sub(_mask_digits, text)
    text = _EMAIL.sub(lambda m: f"{m.group(1)}***{m.group(2)}", text)
    text = _LONG_TOKEN.sub(lambda m: f"{m.group(1)[:4]}…***", text)
    return text
