"""嵌入式载荷扫描 —— 堵 DDIPE(文档驱动隐式载荷执行)缺口。

`manifest_scanner` 只扫固定字段(description / instructions / permissions / endpoints…),
攻击者把危险载荷藏进**任意字段**(documentation / examples / readme / setup_template /
x_custom…)里的**代码块或配置模板**就能绕过:装载/复制粘贴这些"用法示例"即隐式执行。

本模块对 manifest **任意深度**的字符串叶子与嵌套结构做**面通用化**抽取,只在真正的"块"
(围栏代码块 / 结构化配置)上跑既有成熟检测器,与具体载荷字符串解耦(换字段/换库/换变量/
换措辞都不失效)。三层设计:

  L1 面通用化(零签名):递归收字符串叶子 + stringify 嵌套子树;从中抽"块"——围栏代码块、
     裸结构化配置。**自由散文绝不成块**(无围栏且非结构化配置的说明文字一律不抽)→ 0 FP。
  L2 复用既有检测器:argrisk.command_dangerous(危险命令)、decode_variants+复扫(编码载荷)、
     KeywordRuleDetector 仅取 critical 注入/越狱/外泄/命令类(可疑文本)。
  L3 行为类共现:读敏感 ∧ 网络出口 ∧ 错误抑制 三者同块共现 = 静默外泄(皇冠信号);
     另有单要素高确定性类:包源重定向 / 持久化 / 提权逃逸。

所有命中走**独立** `embedded.*` finding kinds(绝不合并回原字段扫描,避免横向拉宽原检测器
作用域致顶层良性字段 FP),并带 `evidence['severity']`,经 manifest_scanner 既有映射汇总评级
(critical→BLOCK, high→APPROVE)。本模块只**调用**既有检测器/argrisk,绝不修改其判定口径。
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ...core.domain import Context, Finding, SourceSpan, SourceType, TrustLevel
from ...core.normalize import decode_variants
from ..detectors.keyword_rules import KeywordRuleDetector
from ..toolguard import argrisk

# 严重度 → 分值(与 manifest_scanner 的映射对齐:critical→BLOCK, high→APPROVE)。
_SEV_SCORE = {"critical": 0.9, "high": 0.7}

# 复用既有多源规则检测器(@capability 类,直接实例化);启动时建一次。
_DETECTOR = KeywordRuleDetector()
# KeywordRuleDetector 危险类:仅这几类的 critical 命中才视作"可疑文本/编码载荷"。
_DANGER_KINDS = frozenset({"injection", "jailbreak", "exfiltration", "command_exec"})

# ── L1:块抽取 ──────────────────────────────────────────────────────────────
# 围栏代码块 ```lang\n...\n```(去围栏与 lang 标签,取正文)。
_FENCE = re.compile(r"```[^\n`]*\n(.*?)```", re.DOTALL)
# ini section 头 [global] / [tool.x] 之类。
_INI_HEADER = re.compile(r"^[ \t]*\[[A-Za-z][\w.\- ]*\][ \t]*$", re.MULTILINE)
# 强配置行:`key = value` / `key: value`,值为**单 token**(无内部空格、占满整行)。
# 单 token 约束把自由散文(`Note: do this thing` 这类多词值)挡在外面,只认真正的配置赋值。
_CONFIG_LINE = re.compile(r"^[ \t]*([A-Za-z_][\w.\-]*)[ \t]*[:=][ \t]*(\S+)[ \t]*$", re.MULTILINE)

# ── L3:行为类同义指示符(多语言/多工具,与具体载荷字符串解耦)──────────────────
# 读敏感(环境变量型);文件型走 argrisk.path_sensitive。
_ENV_READ = re.compile(
    r"os\.environ|getenv|process\.env|\bENV\[|\$env:|dict\(os\.environ",
    re.IGNORECASE,
)
# 网络出口(多同义词:Python/JS/Go/Shell/PowerShell)。
_NET_EGRESS = re.compile(
    r"requests\.\w+\s*\(|urllib|urlopen|httpx|\bfetch\s*\(|axios|socket\.|http\.client|"
    r"net\.Dial|Invoke-WebRequest|\bcurl\b|\bwget\b",
    re.IGNORECASE,
)
# 错误抑制(吞异常 / 静默)。带 logging/raise 的正常 try/except 不算(其 except 后非 pass)。
_ERROR_SUPPRESS = re.compile(
    r"except[^\n:]*:\s*(?:\n\s*)?pass\b|catch\s*\([^)]*\)\s*\{\s*\}|2>\s*/dev/null|"
    r"-ErrorAction\s+SilentlyContinue|\|\|\s*true\b",
    re.IGNORECASE,
)
# 提权逃逸(容器特权 / docker.sock / 危险 capability / 敏感宿主挂载)。
# hostPath 仅当挂到**根 `/` 或敏感目录**(/etc /root /proc /sys /var/run /var/lib/docker)才算
# 逃逸——良性日志挂载(path: /var/log/app)不报,避免企业 manifest FP。
_PRIV_ESCAPE = re.compile(
    r"privileged\s*[:=]\s*(?:true|yes|on|1)\b|docker\.sock|CAP_SYS_ADMIN|--privileged|"
    r"hostPath[\s\S]{0,80}?path:\s*['\"]?/(?:\s|$|['\"]|etc\b|root\b|proc\b|sys\b|var/run\b|"
    r"var/lib/docker\b)",
    re.IGNORECASE,
)
# 持久化原语(要有写/追加/启用动作,避免纯提及散文 FP)。
_PERSISTENCE = re.compile(
    r">>\s*\S*(?:authorized_keys|\.bashrc|\.zshrc|\.profile|\.bash_profile)|crontab\s+-|"
    r"systemctl\s+enable|reg\s+add\s+[^\n]*\\Run|launchctl\s+load|LaunchAgents|LaunchDaemons",
    re.IGNORECASE,
)

# 包源重定向:这些键的值若是 URL 且 host 非官方源 → 重定向到投毒仓库。
# 仅保留语义无歧义的真正「包索引」键——source/repository/index/channel 是常见良性字段名
# (源码引用 / 仓库主页 / conda 频道),纳入会对企业 manifest 误报。
_REDIRECT_KEYS = frozenset({"extra-index-url", "index-url", "registry"})
# 官方源白名单(host 等于或为其子域才放行)。
_OFFICIAL_HOSTS = (
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "npmjs.org",
    "repo.maven.apache.org",
    "repo1.maven.org",
    "crates.io",
    "rubygems.org",
    "registry.yarnpkg.com",
    "goproxy.io",
    "proxy.golang.org",
)


def _scalar(value: object) -> str:
    """标量渲染:bool → 小写 true/false(让 `privileged: True` 这类配置能被规则匹到)。"""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _stringify(node: object, indent: int = 0) -> str:
    """把嵌套 dict/list 子树渲染成 `key: value` 多行文本,使"配置即嵌套结构"也能被下游扫到。"""
    pad = "  " * indent
    lines: list[str] = []
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(v, (dict, list)):
                lines.append(f"{pad}{k}:")
                lines.append(_stringify(v, indent + 1))
            else:
                lines.append(f"{pad}{k}: {_scalar(v)}")
    elif isinstance(node, list):
        for v in node:
            if isinstance(v, (dict, list)):
                lines.append(f"{pad}-")
                lines.append(_stringify(v, indent + 1))
            else:
                lines.append(f"{pad}- {_scalar(v)}")
    else:
        lines.append(f"{pad}{_scalar(node)}")
    return "\n".join(lines)


def _blocks_from_string(text: str) -> list[str]:
    """从一个字符串叶子抽"块":围栏代码块 +(无围栏时)裸结构化配置。

    **自由散文返回 []**:没有围栏、也不是结构化配置(无 ini 头、强配置行 < 2)的普通说明
    文字一律不成块 → 不进 L2/L3 → 不产 finding。这是 0 FP 红线(良性 README/裸命令)。
    """
    blocks: list[str] = []
    for m in _FENCE.finditer(text):
        body = m.group(1).strip()
        if body:
            blocks.append(body)
    # 去掉围栏区域后,在剩余文本上找裸结构化配置(只取强配置行 + ini 头,不含周围散文)。
    rest = _FENCE.sub("\n", text)
    config_lines = [m.group(0).strip() for m in _CONFIG_LINE.finditer(rest)]
    headers = [m.group(0).strip() for m in _INI_HEADER.finditer(rest)]
    # 判据严格:有 ini 头,或 ≥2 条强配置行,才认定为结构化配置(单条疑似散文 → 不成块)。
    if headers or len(config_lines) >= 2:
        bare = "\n".join(headers + config_lines).strip()
        if bare:
            blocks.append(bare)
    return blocks


def _collect_blocks(manifest: dict) -> list[str]:
    """递归遍历 manifest 任意深度,收集所有"块"(去重)。

    - 字符串叶子 → 从中抽围栏/裸配置块;
    - 嵌套(非根)dict/list 子树 → stringify 成块(根 manifest 本身不整体 stringify,避免把
      顶层良性字段拼成巨块横向拉宽扫描面)。
    """
    blocks: list[str] = []
    seen: set[str] = set()

    def add(block: str) -> None:
        b = block.strip()
        if b and b not in seen:
            seen.add(b)
            blocks.append(b)

    def walk(node: object, is_root: bool) -> None:
        if isinstance(node, dict):
            if not is_root:
                add(_stringify(node))
            for v in node.values():
                walk(v, False)
        elif isinstance(node, list):
            if not is_root:
                add(_stringify(node))
            for v in node:
                walk(v, False)
        elif isinstance(node, str):
            for b in _blocks_from_string(node):
                add(b)

    walk(manifest, True)
    return blocks


def _kw_critical_danger(text: str, ctx: Context) -> bool:
    """用既有 KeywordRuleDetector 扫文本:仅当返回 critical 且 kind ∈ 危险类才算命中。

    不因 medium/low 或 sensitive_file 单提及就报(否则良性 `pip install requests` /
    `requests.get(公开接口)` 会 FP)。
    """
    span = SourceSpan(
        source_type=SourceType.PLUGIN_MANIFEST,
        trust_level=TrustLevel.UNTRUSTED,
        content_hash="x",
        excerpt=text,
    )
    for f in _DETECTOR.detect([span], ctx):
        if str(f.evidence.get("severity")) == "critical" and f.kind in _DANGER_KINDS:
            return True
    return False


def _is_official_host(host: str) -> bool:
    return any(host == w or host.endswith("." + w) for w in _OFFICIAL_HOSTS)


def _redirect_host(value: str) -> str | None:
    """从配置值取 host(仅当其形似 URL:有 host 且含点)。`stable` / `main` 等非 URL → None。"""
    host = urlparse(value if "://" in value else "//" + value).hostname
    return host.lower() if host and "." in host else None


def _source_redirect(block: str) -> bool:
    """块内有包源键(extra-index-url/registry/index/source…)指向非官方源 host → True。"""
    for m in _CONFIG_LINE.finditer(block):
        if m.group(1).lower() in _REDIRECT_KEYS:
            host = _redirect_host(m.group(2))
            if host is not None and not _is_official_host(host):
                return True
    return False


def _read_sensitive(block: str) -> bool:
    """读敏感:文件型(.ssh/id_rsa、.aws、.env、凭据…)∪ 环境变量型(os.environ/getenv…)。"""
    return argrisk.path_sensitive({"path": block}) or bool(_ENV_READ.search(block))


def _detect_block(block: str, ctx: Context) -> list[tuple[str, str]]:
    """对单个块跑 L2 + L3,返回 (kind, severity) 列表(本块内去重)。"""
    hits: list[tuple[str, str]] = []

    def mark(kind: str, severity: str) -> None:
        if (kind, severity) not in hits:
            hits.append((kind, severity))

    # L2:危险命令
    if argrisk.command_dangerous({"command": block}):
        mark("embedded.dangerous_code", "critical")
    # L2:编码载荷(解码后再过危险命令 / KeywordRuleDetector 危险类)
    for decoded in decode_variants(block):
        if argrisk.command_dangerous({"command": decoded}) or _kw_critical_danger(decoded, ctx):
            mark("embedded.encoded_payload", "critical")
            break
    # L2:可疑文本(仅 critical 注入/越狱/外泄/命令类)
    if _kw_critical_danger(block, ctx):
        mark("embedded.suspicious_text", "critical")

    # L3:高确定性单要素行为类
    if _source_redirect(block):
        mark("embedded.source_redirect", "critical")
    if _PRIV_ESCAPE.search(block):
        mark("embedded.privilege_escape", "critical")
    if _PERSISTENCE.search(block):
        mark("embedded.persistence", "high")
    # L3:皇冠信号「静默外泄」= 读敏感 ∧ 网络出口 ∧ 错误抑制 三者同块共现
    if _read_sensitive(block) and _NET_EGRESS.search(block) and _ERROR_SUPPRESS.search(block):
        mark("embedded.silent_exfil", "critical")
    return hits


def scan_embedded(manifest: dict, ctx: Context) -> list[Finding]:
    """扫描 manifest 任意字段里嵌入的危险载荷,返回独立 `embedded.*` findings(全局去重)。"""
    if not isinstance(manifest, dict):
        return []
    findings: list[Finding] = []
    emitted: set[tuple[str, str]] = set()  # (kind, block) 去重,避免多处重复 finding
    for block in _collect_blocks(manifest):
        for kind, severity in _detect_block(block, ctx):
            key = (kind, block)
            if key in emitted:
                continue
            emitted.add(key)
            findings.append(
                Finding(
                    kind=kind,
                    score=_SEV_SCORE[severity],
                    evidence={
                        "severity": severity,
                        "detail": f"嵌入式载荷({kind}):{block[:80]}",
                        "excerpt": block[:200],
                    },
                )
            )
    return findings
