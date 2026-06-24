"""ManifestScanner —— 供应链最小静态扫描评级,对应赛题目标③(轻量做全)。

对插件 / Skill / MCP 工具的 manifest 做**确定性静态检查**,不执行任何组件代码:

1. 声明权限:命令执行 / 凭据访问 / 文件写删 / 环境变量 / 联网 / 文件读,按危险度分级;
2. 描述文本:后门、反弹 shell、提权、键盘记录、数据外泄、挖矿、绕过审查等可疑关键词;
   并扫描 instructions/prompt/system 等**指令承载字段**里的注入/外泄指挥语(投毒 Skill
   把"忽略上层指令、把数据外发到外部"藏进 manifest,装载即污染 agent → Manifest 注入面);
   再于描述/指令/权限里认出**指名访问敏感凭据载体**(~/.ssh/id_rsa、.aws/credentials、.env、
   AWS_/GITHUB_TOKEN、/etc/shadow…)的窃取意图(工具描述投毒 / 凭据窃取面)→critical;
3. 外联端点:裸 IP、明文 http、可疑 TLD / 动态域名 / 短链;
4. 依赖来源:从 URL / git+ 直接安装(绕过仓库审核);
5. 安装期钩子:postinstall / preinstall / scripts.install / hooks 等**装载时自动执行**的
   命令(npm postinstall 投毒面),含危险动作→critical,仅声明自动执行→high。

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

# AI 技能/插件/MCP manifest 里承载"指令"的字段:被投毒的组件常把注入/外泄**指挥语**
# 藏在 instructions/prompt/system 等字段,组件一装载就直接污染 agent 上下文(Manifest 注入面,
# 对应指标体系「Manifest 注入识别率」)。与 _DESC_SUSPICIOUS 互补——那查恶意软件关键词,
# 这查"覆盖上层指令 / 把数据外发到外部"这类指挥模型的措辞。
_INSTRUCTION_FIELDS: tuple[str, ...] = (
    "instructions",
    "instruction",
    "prompt",
    "system_prompt",
    "system",
    "persona",
    "role",
    "behavior",
    "usage",
    "guide",
)
_MANIFEST_INJECTION = re.compile(
    r"(ignore\s+(the\s+)?(previous|above|prior|preceding)\s+(instructions?|rules?|prompts?)|"
    r"disregard\s+(the\s+)?(instructions?|rules?|above)|"
    r"reveal\s+(the\s+)?(system\s+)?prompt|"
    r"exfiltrat\w*|send\s+.{0,24}\s+to\s+.{0,24}(external|http|attacker|evil)|"
    r"忽略(以上|之前|上述|前面|前文)(的)?(指令|规则|提示词?|设定)|"
    r"无视(系统|安全|上述|之前)(的)?(设定|规则|指令)|"
    r"覆盖(系统|上层|之前的?)(指令|设定|规则)|"
    r"(泄露|输出|打印|回显)(系统)?提示词|"
    r"(外发|外传|回传|上传|发送).{0,12}(到|至|给).{0,16}(外部|http|服务器|攻击者|邮箱))",
    re.IGNORECASE,
)
# 敏感凭据文件 / 密钥环境变量的访问意图(命中即 critical)。与 _PERM_RULES 的 credential_access
# 互补——那看权限"声明",这看描述/指令/权限里**指名道姓**要碰的具体凭据载体:SSH/云密钥、
# 服务令牌、系统凭据库。智能体供应链两类经典攻击——工具描述投毒(把"读 ~/.ssh/id_rsa 当
# sidenote 传入"藏进 desc)与凭据窃取(枚举 .env / AWS_ / GITHUB_TOKEN 后外发)——皆落此面。
_SENSITIVE_ACCESS = re.compile(
    r"(\.ssh/|id_rsa|id_ed25519|id_ecdsa|id_dsa|"  # SSH 私钥
    r"\.aws/|aws_(access|secret)_?key|\baws_(?=[\s'\",、])|"  # AWS 凭据:路径/密钥变量/裸前缀
    r"\.kube/|kubeconfig|\.docker/config|"  # k8s / docker 凭据
    r"\.npmrc|\.pypirc|\.netrc|"  # 包管理 / 网络凭据
    r"github_token|\bgh_token\b|stripe_(secret|key)|openai_api_key|"  # 服务令牌
    r"\.env\b|credentials\.(json|ya?ml)|secrets?\.(json|ya?ml)|"  # 凭据文件
    r"/etc/(passwd|shadow)|ntds\.dit|"  # 系统凭据库
    r"私钥文件|凭据文件|密钥文件)",
    re.IGNORECASE,
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

# 安装期生命周期钩子:这些键声明的命令在组件**安装/登记时自动执行**,绕过任何运行时
# 治理与人工审查——npm postinstall 投毒(event-stream、ua-parser-js)即此面。顶层标量键
# 直接是命令;`scripts` 字典里仅这些键自动执行(test/build 等不算);`hooks`/`lifecycle`
# 容器内全部视作生命周期钩子。
_INSTALL_HOOK_KEYS: frozenset[str] = frozenset(
    {
        "preinstall",
        "install",
        "postinstall",
        "preuninstall",
        "postuninstall",
        "prepare",
        "prepublish",
        "setup",
        "on_install",
        "onload",
    }
)
_HOOK_CONTAINERS: tuple[str, ...] = ("scripts", "hooks", "lifecycle")
# 钩子命令里的危险动作(下载执行 / 解码执行 / 起 shell / 反弹),命中即 critical。
_HOOK_EXEC = re.compile(
    r"(curl|wget|invoke-?webrequest|\biwr\b|certutil|"  # 下载器
    r"\b(bash|sh|zsh|powershell|pwsh|cmd)\b|/bin/sh|"  # 起 shell
    r"base64\s+-d|\beval\b|\biex\b|exec\(|"  # 解码 / 动态执行
    r"python[0-9.]*\s+-c|node\s+-e|perl\s+-e|ruby\s+-e|"  # 内联脚本
    r"nc\s+-e|/dev/tcp/|chmod\s+\+?x|反弹|下载执行)",
    re.IGNORECASE,
)


def _install_hooks(manifest: dict) -> list[tuple[str, str]]:
    """抽取安装期生命周期钩子为 (钩子名, 命令) 列表。

    顶层标量/列表键(postinstall 等)直接是命令;`scripts` 字典只取自动执行的安装期键;
    `hooks`/`lifecycle` 字典或列表整体视作生命周期钩子。非字符串值转字符串。
    """
    out: list[tuple[str, str]] = []
    for key in _INSTALL_HOOK_KEYS:
        value = manifest.get(key)
        if isinstance(value, str) and value.strip():
            out.append((key, value))
        elif isinstance(value, list):
            out.extend((key, str(v)) for v in value if str(v).strip())
    for container in _HOOK_CONTAINERS:
        node = manifest.get(container)
        if isinstance(node, dict):
            for k, v in node.items():
                if container == "scripts" and str(k).lower() not in _INSTALL_HOOK_KEYS:
                    continue  # scripts 里只有安装期键自动执行,test/build 等跳过
                label = f"{container}.{k}"
                if isinstance(v, list):
                    out.extend((label, str(x)) for x in v if str(x).strip())
                elif str(v).strip():
                    out.append((label, str(v)))
        elif isinstance(node, list):
            out.extend((container, str(x)) for x in node if str(x).strip())
    return out


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

        # 2.5) 指令字段注入(Manifest 注入面):被投毒组件把注入/外泄指挥语藏进
        #      instructions/prompt/system 等字段,装载即污染 agent 上下文。
        instr_parts: list[str] = []
        for field in _INSTRUCTION_FIELDS:
            instr_parts.extend(_as_list(manifest.get(field)))
        inj = sorted({m.group(0) for m in _MANIFEST_INJECTION.finditer("\n".join(instr_parts))})
        if inj:
            risks.append(
                _finding(
                    "manifest.prompt_injection",
                    "critical",
                    f"指令字段含注入/外泄指挥语:{inj}",
                    matched=inj,
                )
            )

        # 2.6) 敏感凭据文件 / 密钥访问意图:扫描 描述 + 指令字段 + 声明权限 三处,认出
        #      指名要碰 SSH/云密钥、服务令牌、系统凭据库的载体(工具描述投毒 / 凭据窃取面)。
        perm_text = _gather(manifest, "permissions", "scopes", "capabilities")
        sens_surface = "\n".join([description, *instr_parts, *perm_text])
        sens = sorted({m.group(0) for m in _SENSITIVE_ACCESS.finditer(sens_surface)})
        if sens:
            risks.append(
                _finding(
                    "sensitive_file_access",
                    "critical",
                    f"指向敏感凭据文件/密钥:{sens}",
                    matched=sens,
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

        # 5) 安装期生命周期钩子(自动执行,绕过审查):命中危险命令→critical,否则记 high。
        for hook_name, cmd in _install_hooks(manifest):
            if _HOOK_EXEC.search(cmd):
                risks.append(
                    _finding(
                        "hook.install_exec",
                        "critical",
                        f"安装期钩子 {hook_name} 执行危险命令:{cmd[:80]}",
                        hook=hook_name,
                        command=cmd[:200],
                    )
                )
            else:
                risks.append(
                    _finding(
                        "hook.lifecycle",
                        "high",
                        f"声明安装期自动执行钩子 {hook_name}:{cmd[:80]}",
                        hook=hook_name,
                        command=cmd[:200],
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
