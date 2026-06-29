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
        # Armenian 小写(UTS#39 confusables.txt MA 行,亚美尼亚小写 → 单个拉丁 ASCII)
        "օ": "o",  # U+0585 OH → o(攻击常用:ignօre）
        "հ": "h",  # U+0570 HO → h
        "ռ": "n",  # U+057C RA → n（同形 ո/U+0578 VO 已在表中,此处不重复）
        "ս": "u",  # U+057D SEH → u
        "ա": "w",  # U+0561 AYB → w
        "ւ": "i",  # U+0582 YIWN → i
        "ց": "g",  # U+0581 CO → g
        "ք": "f",  # U+0584 KEH → f
        "գ": "q",  # U+0563 GIM → q
        "զ": "q",  # U+0566 ZA → q
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


# ---- 递归解码:把藏进 base64 / hex / URL 编码 / ROT13 / HTML 数字实体的指令解出来供复扫 ----
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
# base32(RFC4648 字母表 A-Z2-7):把指令 base32 编码绕过关键词匹配,与 base64/hex 同属"解码后复扫"。
_B32 = re.compile(r"[A-Z2-7]{16,}={0,6}")
# URL-safe base64 字符替换(-_ → +/),用于兜底解 urlsafe 变体。
_URLSAFE_B64 = str.maketrans("-_", "+/")
# HTML 数字字符引用:&#105; / &#x69;。把字母编码成数字实体(`&#105;gnore previous…`)是网页/
# 文档绕过关键词匹配的常见手法。**只解数字引用**——具名实体(&lt; &amp; &nbsp;)正常文档遍地都是,
# 解了反而误伤;字母的数字引用几乎只见于刻意规避,判别力强、低误报。
_HTML_NUMREF = re.compile(r"&#(x[0-9a-fA-F]+|\d+);")


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


def _b32(blob: str) -> str:
    """base32 解码;补足 '=' 到 8 的倍数。非 base32/解不出 → 返回 ''(由上层'解出物≠原文'丢弃)。"""
    body = blob.rstrip("=")
    try:
        padded = body + "=" * (-len(body) % 8)
        return base64.b32decode(padded, casefold=False).decode("utf-8", "ignore")
    except (binascii.Error, ValueError):
        return ""


def _html_numref(s: str) -> str:
    """把 HTML 数字字符引用(&#105; / &#x69;)还原为字符;非法/越界引用原样保留。"""

    def repl(m: re.Match[str]) -> str:
        body = m.group(1)
        try:
            cp = int(body[1:], 16) if body[0] in "xX" else int(body)
        except ValueError:
            return m.group(0)
        return chr(cp) if 0 <= cp <= 0x10FFFF else m.group(0)

    return _HTML_NUMREF.sub(repl, s)


# 解码产物「可读文本」门:base32/base64/hex 命中真实大写/编码 token(AWS access key、TOTP、
# DNSSEC 标签、hex 摘要)时解出的是二进制垃圾——常夹 C0/C1 控制字节,这些控制字节又给
# `\bDAN\b`/`\bAIM\b` 这类短规则凑出词边界致误报(复审 #96:`DNSEC3R2KZN23534`→`\x1bdAn:V[|`)。
# 真实隐藏载荷解出的是干净可读文本。故解码产物须先过本门才作为复扫变体:无 C0/C1 控制字符
# (\t\n\r 除外)且可打印/文字字符占比够高;否则当二进制垃圾丢弃,堵「编码 token→噪声→短规则」。
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_CLEAN_MIN_RATIO = 0.9


def _is_clean_text(s: str) -> bool:
    """解码产物是否为可读文本(供复扫的前置门):无控制噪声、可打印占比 ≥ 阈值。"""
    if not s or _CTRL.search(s):
        return False
    printable = sum(1 for ch in s if ch.isprintable() or ch in "\t\n\r")
    return printable / len(s) >= _CLEAN_MIN_RATIO


def _untag(text: str) -> str:
    """还原 Unicode Tag 块走私(U+E0000–E007F)为 ASCII 副本 —— 区别于 normalize() 的剥除。

    Tag char 本身即载荷(cp-0xE0000=ASCII),剥掉等于删指令;这里**还原**成可见 ASCII 供复扫。
    仅映射解出 0x20–0x7E 可见 ASCII 的 tag char;语言标记/CANCEL/DEL 等非可见标记丢弃;
    非该区间字符原样保留 → 正常文本(无 tag char)返回值与输入逐字符相同(零开销早退)。
    """
    if not any(0xE0000 <= ord(c) <= 0xE007F for c in text):
        return text
    out: list[str] = []
    for c in text:
        cp = ord(c)
        if 0xE0000 <= cp <= 0xE007F:
            d = cp - 0xE0000
            if 0x20 <= d <= 0x7E:
                out.append(chr(d))
            # 非可见 tag 标记(语言标记/CANCEL/DEL)丢弃
        else:
            out.append(c)
    return "".join(out)


def decode_variants(text: str, depth: int = 2) -> list[str]:
    """抽取并解码文本里的编码块(base64/hex/URL/ROT13),递归至多 depth 层。

    解不出可读文本 / 无意义则丢弃,故正常 base64(图片、随机令牌)不会刷出垃圾命中。
    解码产物还须过 `_is_clean_text` 可读门:二进制垃圾(真实大写/编码 token 解出的控制字节
    噪声)不作为复扫变体,避免撞上短规则误报(复审 #96)。
    """
    out: list[str] = []
    seen: set[str] = set()
    frontier = [text]
    for _ in range(max(1, depth)):
        nxt: list[str] = []
        for s in frontier:
            cands: list[str] = [_b64(m.group(0)) for m in _B64.finditer(s)]
            cands += [_hexd(m.group(0)) for m in _HEX.finditer(s)]
            cands += [_b32(m.group(0)) for m in _B32.finditer(s)]
            if "-" in s or "_" in s:  # URL-safe base64 兜底:-_→+/ 后按标准 base64 再抽
                su = s.translate(_URLSAFE_B64)
                cands += [_b64(m.group(0)) for m in _B64.finditer(su)]
            if "%" in s:
                cands.append(unquote(s))
            if "&#" in s:
                cands.append(_html_numref(s))
            cands.append(_untag(s))  # Unicode Tag 块走私(U+E0000–E007F)还原 ASCII 副本
            try:
                cands.append(codecs.decode(s, "rot13"))  # ROT13 只影响 a-z,中文不变
            except (UnicodeError, ValueError):
                pass
            for c in cands:
                c = (c or "").strip()
                if c and c != s and c not in seen and _is_clean_text(c):
                    seen.add(c)
                    out.append(c)
                    nxt.append(c)
        frontier = nxt
        if not frontier:
            break
    return out
