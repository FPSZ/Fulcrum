"""ManifestScanner —— 供应链最小静态扫描评级,对应赛题目标③(轻量做全)。

对插件 / Skill / MCP 工具的 manifest 做**确定性静态检查**,不执行任何组件代码:

1. 声明权限:命令执行 / 凭据访问 / 文件写删 / 环境变量 / 联网 / 文件读,按危险度分级;
2. 描述文本:后门、反弹 shell、提权、键盘记录、数据外泄、挖矿、绕过审查等可疑关键词;
3. 外联端点:裸 IP、明文 http、可疑 TLD / 动态域名 / 短链;
4. 依赖来源:从 URL / git+ 直接安装(绕过仓库审核)。

每条命中产出一条 Finding(`score`∈[0,1] + `evidence.severity`),按最严重项汇总为
ScanReport.rating:critical→block,high→approve(人工复核),medium→sanitize,否则 allow。

定位(与 dev 骨架一致):供应链扫描是**组件登记/上线时的离线关切**,不在每请求安全管线里,
经独立流程(如 `python -m fulcrum.scan`)调用。Semgrep 代码扫描 / 依赖图 / 行为启发式为
M4 增强(见路线图),不在本最小闭环内。
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ...core.domain import Context, Disposition, Finding, ScanReport
from ...core.registry import capability

# 严重度 → 分值 / 排序;rating 由最严重项映射。
_SEV_SCORE = {"low": 0.3, "medium": 0.5, "high": 0.7, "critical": 0.9}
_SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_RATING_BY_SEV = {
    "critical": Disposition.BLOCK,
    "high": Disposition.APPROVE,
    "medium": Disposition.SANITIZE,
    "low": Disposition.ALLOW,
}

# 声明权限 → (finding kind, 严重度)。按关键词匹配权限字符串(中英)。
_PERM_RULES: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (
        re.compile(r"(shell|exec|command|subprocess|spawn|\bprocess\b|os\.system|run_?cmd)", re.I),
        "perm.command_exec",
        "critical",
    ),
    (
        re.compile(r"(credential|secret|keychain|token|password|私钥|密钥|凭据|凭证|口令)", re.I),
        "perm.credential_access",
        "critical",
    ),
    (
        re.compile(
            r"(file[._ ]?write|fs[._ ]?write|write_?file|delete|remove|filesystem|文件写|删除)",
            re.I,
        ),
        "perm.file_write",
        "high",
    ),
    (re.compile(r"(env(ironment)?|环境变量)", re.I), "perm.env_access", "high"),
    # 声明联网本身常见,记为低风险信号(与可疑描述/外联组合时才显著)。
    (
        re.compile(r"(network|http|socket|outbound|fetch|联网|网络|外联)", re.I),
        "perm.network",
        "low",
    ),
    (re.compile(r"(file[._ ]?read|read_?file|文件读)", re.I), "perm.file_read", "low"),
)

# 描述文本可疑关键词(命中即 critical)。
_DESC_SUSPICIOUS = re.compile(
    r"(backdoor|reverse\s*shell|rootkit|keylog|exfiltrat|crypto\s*miner|\bminer\b|obfuscat|"
    r"bypass\s*(security|auth|sandbox|review)|steal\s*(credential|password|token)|"
    r"后门|反弹\s*shell|提权|键盘记录|挖矿|窃取|隐蔽外联|绕过\s*(安全|审查|沙箱|检测))",
    re.IGNORECASE,
)
# 可疑 TLD / 动态域名 / 短链(粗启发,medium)。
_SUSPICIOUS_HOST = re.compile(
    r"(\.(xyz|top|tk|ml|ga|cf|gq|ru|su|click|zip|mov)$|ngrok\.|duckdns\.|no-ip\.|bit\.ly|tinyurl)",
    re.IGNORECASE,
)
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _as_list(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    return []


def _gather(manifest: dict, *keys: str) -> list[str]:
    out: list[str] = []
    for k in keys:
        out.extend(_as_list(manifest.get(k)))
    return out


def _finding(kind: str, severity: str, detail: str, **extra: object) -> Finding:
    return Finding(
        kind=kind,
        score=_SEV_SCORE[severity],
        evidence={"severity": severity, "detail": detail, **extra},
    )


@capability("scanner", "manifest")
class ManifestScanner:
    """静态 manifest 扫描器。注册名 `manifest`,经独立供应链流程(scan CLI)调用。"""

    def scan(self, manifest: dict, ctx: Context) -> ScanReport:
        name = str(manifest.get("name", "unknown"))
        version = manifest.get("version")
        component_id = f"{name}@{version}" if version else name
        risks: list[Finding] = []

        # 1) 声明权限
        seen_kinds: set[str] = set()
        for perm in _gather(manifest, "permissions", "scopes", "capabilities"):
            for pattern, kind, severity in _PERM_RULES:
                if pattern.search(perm) and kind not in seen_kinds:
                    seen_kinds.add(kind)
                    risks.append(_finding(kind, severity, f"声明高危权限:{perm}", permission=perm))

        # 2) 描述可疑关键词
        description = str(manifest.get("description") or manifest.get("desc") or "")
        hits = sorted({m.group(0) for m in _DESC_SUSPICIOUS.finditer(description)})
        if hits:
            risks.append(
                _finding(
                    "desc.suspicious", "critical", f"描述含可疑意图关键词:{hits}", matched=hits
                )
            )

        # 3) 外联端点
        for ep in _gather(manifest, "endpoints", "urls", "hosts", "outbound"):
            host = urlparse(ep if "://" in ep else f"//{ep}").hostname or ep
            if _IPV4.match(host):
                risks.append(_finding("endpoint.raw_ip", "high", f"外联裸 IP:{ep}", endpoint=ep))
            elif _SUSPICIOUS_HOST.search(host):
                risks.append(
                    _finding(
                        "endpoint.suspicious_host", "medium", f"可疑外联域名:{ep}", endpoint=ep
                    )
                )
            elif ep.lower().startswith("http://"):
                risks.append(
                    _finding(
                        "endpoint.plaintext_http", "medium", f"明文 http 外联:{ep}", endpoint=ep
                    )
                )

        # 4) 依赖来源
        for dep in _gather(manifest, "dependencies", "requires", "deps"):
            low = dep.lower()
            if "://" in low or low.startswith("git+") or low.startswith(("http", "ftp")):
                risks.append(
                    _finding(
                        "dep.install_from_url",
                        "high",
                        f"从 URL/源码直接安装依赖:{dep}",
                        dependency=dep,
                    )
                )

        rating = self._rating(risks)
        return ScanReport(component_id=component_id, rating=rating, risks=risks)

    @staticmethod
    def _rating(risks: list[Finding]) -> Disposition:
        if not risks:
            return Disposition.ALLOW
        worst = max(risks, key=lambda f: _SEV_RANK.get(str(f.evidence.get("severity")), 0))
        return _RATING_BY_SEV.get(str(worst.evidence.get("severity")), Disposition.ALLOW)
