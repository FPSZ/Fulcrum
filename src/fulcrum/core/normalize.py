"""匹配前归一化 / 解码 —— 规则匹配前先抹平 Unicode 走私与编码混淆。

方法论对齐 OWASP LLM01:2025 缓解("输入归一化")与 Unicode UTS#39(Confusables)。
原文保持不动(供审计取证),本模块只产出**匹配副本**:检测器在这些副本上跑既有规则,
从而在不改规则语义的前提下,救回 全角/同形字/零宽/双向/leetspeak/嵌套编码 等绕过。
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
from urllib.parse import unquote

# 不可见/控制符码点(用码点构造,避免源码里藏不可见字符):
# 零宽 200B-200D、词连接 2060、BOM FEFF、软连字符 00AD、双向 202A-202E/2066-2069、
# 变体选择符 FE00-FE0F、Unicode Tag 块 E0000-E007F(ASCII 走私)。
_INVISIBLE_CODEPOINTS = (
    [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD]
    + list(range(0x202A, 0x202F))
    + list(range(0x2066, 0x206A))
    + list(range(0xFE00, 0xFE10))
    + list(range(0xE0000, 0xE0080))
)
_INVISIBLE = re.compile("[" + "".join(re.escape(chr(c)) for c in _INVISIBLE_CODEPOINTS) + "]")

# 高频同形字 → 拉丁(UTS#39 confusables 子集:西里尔 / 希腊,攻击最常用这批替 a/e/o/p/c…)。
_CONFUSABLES = str.maketrans(
    {
        # Cyrillic 小写
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "х": "x",
        "ѕ": "s",
        "і": "i",
        "ј": "j",
        "к": "k",
        "м": "m",
        "н": "h",
        "т": "t",
        "в": "b",
        "ԁ": "d",
        "ɡ": "g",
        "ո": "n",
        # Cyrillic 大写
        "А": "A",
        "Е": "E",
        "О": "O",
        "Р": "P",
        "С": "C",
        "У": "Y",
        "Х": "X",
        "К": "K",
        "М": "M",
        "Н": "H",
        "Т": "T",
        "В": "B",
        # Greek
        "ο": "o",
        "ν": "v",
        "α": "a",
        "ρ": "p",
        "ε": "e",
        "ι": "i",
        "κ": "k",
        "τ": "t",
        "υ": "u",
        "χ": "x",
        "Ο": "O",
        "Α": "A",
        "Ε": "E",
        "Ρ": "P",
    }
)

# leetspeak 映射(谨慎、有损;仅用于"去 leet 副本"辅助匹配,不动原文/主副本)。
_LEET = str.maketrans(
    {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}
)


def normalize(text: str) -> str:
    """安全归一化:NFKC(全角→半角)+ 剥不可见控制符 + 同形字折叠。对正常中英文本无损。"""
    t = unicodedata.normalize("NFKC", text)
    t = _INVISIBLE.sub("", t)
    return t.translate(_CONFUSABLES)


def deleet(text: str) -> str:
    """去 leetspeak(有损,作为附加匹配副本)。"""
    return text.translate(_LEET)


def match_variants(text: str) -> list[str]:
    """返回供规则匹配的副本集合(去重):原文 / 归一化 / 去 leet。"""
    norm = normalize(text)
    variants = [text, norm, deleet(norm)]
    seen: set[str] = set()
    out: list[str] = []
    for v in variants:
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out


# ---- 递归解码:把藏进 base64 / hex / URL 编码 / ROT13 的指令解出来供复扫 ----
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")


def _b64(blob: str) -> str:
    try:
        return base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False).decode(
            "utf-8", "ignore"
        )
    except (binascii.Error, ValueError):
        return ""


def _hexd(blob: str) -> str:
    try:
        return bytes.fromhex(blob).decode("utf-8", "ignore")
    except ValueError:
        return ""


def decode_variants(text: str, depth: int = 2) -> list[str]:
    """抽取并解码文本里的编码块(base64/hex/URL/ROT13),递归至多 depth 层。

    解不出可读文本 / 无意义则丢弃,故正常 base64(图片、随机令牌)不会刷出垃圾命中。
    """
    out: list[str] = []
    seen: set[str] = set()
    frontier = [text]
    for _ in range(max(1, depth)):
        nxt: list[str] = []
        for s in frontier:
            cands: list[str] = [_b64(m.group(0)) for m in _B64.finditer(s)]
            cands += [_hexd(m.group(0)) for m in _HEX.finditer(s)]
            if "%" in s:
                cands.append(unquote(s))
            try:
                cands.append(codecs.decode(s, "rot13"))  # ROT13 只影响 a-z,中文不变
            except (UnicodeError, ValueError):
                pass
            for c in cands:
                c = (c or "").strip()
                if c and c != s and c not in seen:
                    seen.add(c)
                    out.append(c)
                    nxt.append(c)
        frontier = nxt
        if not frontier:
            break
    return out
