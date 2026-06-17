"""敏感信息脱敏 —— 给**审计/展示用**的文本摘要打码,避免审计系统自身成为泄露点。

对应安全问题 01 §4.6/§4.8:「对审计日志做脱敏,避免审计系统自身泄露」。确定性正则,
覆盖政务场景常见敏感量:身份证号、手机号、邮箱、显式密钥/口令、长不透明令牌。

**只用于审计/展示副本**(如判定点 evidence 的 excerpt),不改流向检测器与企业智能体的原文
——检测需要看到全文,脱敏只防"留痕环节把敏感数据落进库"。纯函数、无副作用。
"""

from __future__ import annotations

import re

# 顺序敏感:先打码结构化强标识(密钥KV/身份证/手机/邮箱),最后兜底长令牌。
# 各替换结果含 * 或 …,会打断后续 [A-Za-z0-9_-] 连续段,故不会被长令牌规则二次命中。
_SECRET_KV = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"密码|口令|密钥|凭据|凭证)(\s*[:=]\s*)(\"?)([^\s\"]{3,})"
)
_ID_CARD = re.compile(r"(?<![0-9])(\d{6})(\d{8})(\d{3}[0-9Xx])(?![0-9])")
_PHONE = re.compile(r"(?<!\d)(1[3-9]\d)(\d{4})(\d{4})(?!\d)")
_EMAIL = re.compile(r"(\w)[\w.+-]*(@[\w.-]+\.\w+)")
_LONG_TOKEN = re.compile(r"(?<![A-Za-z0-9_\-])([A-Za-z0-9_\-]{24,})(?![A-Za-z0-9_\-])")


def redact(text: str) -> str:
    """对文本做敏感信息打码,返回脱敏后的副本(原值不可从结果恢复)。"""
    if not text:
        return text
    text = _SECRET_KV.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}***", text)
    text = _ID_CARD.sub(lambda m: f"{m.group(1)}{'*' * 8}{m.group(3)}", text)
    text = _PHONE.sub(lambda m: f"{m.group(1)}****{m.group(3)}", text)
    text = _EMAIL.sub(lambda m: f"{m.group(1)}***{m.group(2)}", text)
    text = _LONG_TOKEN.sub(lambda m: f"{m.group(1)[:4]}…***", text)
    return text
