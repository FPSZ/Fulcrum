"""ManifestScanner —— 供应链最小静态扫描评级,对应赛题目标③(轻量做全)。

对插件 / Skill / MCP 工具的 manifest 做**确定性静态检查**,不执行任何组件代码:

1. 声明权限:命令执行 / 凭据访问 / 文件写删 / 环境变量 / 联网 / 文件读,按危险度分级;
2. 描述文本:后门、反弹 shell、提权、键盘记录、数据外泄、挖矿、绕过审查等可疑关键词;
   并扫描 instructions/prompt/system 等**指令承载字段**里的注入/外泄指挥语(投毒 Skill
   把"忽略上层指令、把数据外发到外部"藏进 manifest,装载即污染 agent → Manifest 注入面);
   再于描述/指令/权限里认出**指名访问敏感凭据载体**(~/.ssh/id_rsa、.aws/credentials、.env、
   AWS_/GITHUB_TOKEN、/etc/shadow…)的窃取意图(工具描述投毒 / 凭据窃取面)→critical;
3. 外联端点:裸 IP、明文 http、可疑 TLD / 动态域名 / 短链;
4. 依赖来源:从 URL / git+ 直接安装(绕过仓库审核);版本号畸高(依赖混淆抢解析);
   依赖名与知名包**形近抢注**(typosquatting——如 reqeusts/colourama/python-dateutil2;
   PEP 503 归一后仍与白名单知名包相差 1~2 个编辑 → high 人工复核,而非精确同名的安全变体);
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
from ...core.normalize import decode_variants, match_variants
from ...core.registry import capability
from .embedded_payload import scan_embedded


def _regex_hits(pattern: re.Pattern[str], text: str, *, decode: bool = False) -> list[str]:
    """在归一化/去leet(+可选解码)多副本上跑正则,抹平全角/同形/零宽(+base64/hex)绕过。

    与 keyword_rules / embedded_payload 同口径:此前 manifest 三大正则只在**原始**字段文本上跑
    ASCII 正则,离线 CLI(python -m fulcrum.scan)路径无任何归一化 → 全角/同形字/编码混淆可绕过。
    decode=True 追加 decode_variants(指令/描述字段用,抓藏在 base64/hex 里的注入语)。
    """
    variants = match_variants(text)
    if decode:
        variants = variants + decode_variants(text)
    hits: set[str] = set()
    for variant in variants:
        hits.update(m.group(0) for m in pattern.finditer(variant))
    return sorted(hits)


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
    r"(外发|外传|回传|上传|发送).{0,12}(到|至|给).{0,16}(外部|http|服务器|攻击者|邮箱)|"
    # 隐蔽外泄指令(rug-pull / 描述投毒:批准后把"偷偷抄送全部记录""别告诉用户"塞进 desc):
    r"(附|附上|附带|并附|额外附).{0,8}(全部|所有|全量).{0,12}(聊天|对话|记录|历史|消息|内容)|"
    r"不要\s*(告诉|让|通知)\s*(用户|任何人|对方))",
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


def _dep_items(manifest: dict) -> list[tuple[str, str]]:
    """依赖抽成 (名, 版本/源) 列表。兼容三态:dict{名:版本}、list[名]、裸字符串。

    样例常把 deps 写成 `{'reqeusts':'2.31.0', 'x':'git+https://…'}`(dict),旧 `_gather`
    只认 str/list 会整块漏掉——故单列。
    """
    out: list[tuple[str, str]] = []
    for key in ("dependencies", "requires", "deps"):
        node = manifest.get(key)
        if isinstance(node, dict):
            out.extend((str(k), str(v)) for k, v in node.items())
        elif isinstance(node, list):
            out.extend((str(v), "") for v in node)
        elif isinstance(node, str) and node.strip():
            out.append((node, ""))
    return out


_VER_MAJOR = re.compile(r"^\D*(\d+)")


def _abnormal_version(spec: str) -> bool:
    """主版本号畸高(≥50)→ 依赖混淆典型信号(攻击者发超高版本抢解析,如 99.0.1 / ^100.0.0)。

    排除日历版本(CalVer):`pytz==2024.1`、`certifi==2024.2.2`、`tzdata==2024.1` 等正规包主版本
    是四位年份,不该判异常。年份区间(1900–2100)一律豁免;真·抢解析用的是 99/100/9999 等非年份畸高值。
    """
    m = _VER_MAJOR.match(spec.strip())
    if not m:
        return False
    major = int(m.group(1))
    if 1900 <= major <= 2100:  # CalVer 年份,正规
        return False
    return major >= 50


_PKG_SEP = re.compile(r"[-_.]+")


def _normalize_pkg(name: str) -> str:
    """PEP 503 风格归一:小写 + 连续 `-_.` 收敛为单个 `-` + 去首尾 `-`。

    使 `Python_DateUtil`、`python.dateutil`、`python-dateutil` 归一为同一串 → 视作同包(安全变体,
    不算 typosquat);而 `python-dateutil2` 归一后仍多一个字符 → 保留差异供编辑距离判定。
    """
    return _PKG_SEP.sub("-", name.strip().lower()).strip("-")


# 依赖名 typosquatting(形近抢注):攻击者发布与知名包**视觉/拼写极近**的包名(reqeusts↔requests、
# colourama↔colorama、python-dateutil2↔python-dateutil),诱导误装。检测=对每个依赖名与下方
# 精选知名包白名单比对**归一化后的编辑距离**:精确匹配(含大小写/分隔符变体)= 安全;相差 1~2 个
# 编辑但非零 = 疑似抢注 → high(人工复核,非 block——编辑距离是启发式,极少数可能是合法新包)。
# 白名单只收**确实高下载量**的目标包(PyPI/npm 头部),名字彼此分得开;已知成对合法包(boto/boto3、
# psycopg/psycopg2、request/requests)两端都收,精确匹配即安全、不互判抢注。统一存归一化形式。
# 空格分隔的原始清单(经 _normalize_pkg 归一后入 frozenset;紧凑且 ruff format 稳定)。
_POPULAR_RAW = (
    # ── PyPI 头部 ──
    "requests request urllib3 setuptools certifi charset-normalizer idna wheel python-dateutil "
    "pyyaml numpy pandas boto boto3 botocore s3transfer packaging typing-extensions click "
    "jinja2 markupsafe colorama cryptography importlib-metadata protobuf flask werkzeug "
    "itsdangerous sqlalchemy pydantic pydantic-core fastapi starlette uvicorn httpx httpcore "
    "anyio sniffio aiohttp aiosignal frozenlist multidict yarl django djangorestframework "
    "celery redis pymongo psycopg psycopg2 psycopg2-binary pymysql pillow matplotlib scipy "
    "scikit-learn tensorflow torch keras transformers tqdm rich typer poetry virtualenv pipenv "
    "pytest pytest-cov coverage mypy flake8 black isort pylint ruff bandit pre-commit sphinx "
    "docutils babel markdown beautifulsoup4 soupsieve lxml html5lib openpyxl pyarrow dask numba "
    "sympy networkx gunicorn gevent greenlet opencv-python imageio seaborn plotly bokeh "
    "statsmodels nltk spacy gensim xgboost lightgbm joblib cloudpickle tabulate termcolor wrapt "
    "decorator cachetools pygments prompt-toolkit paramiko fabric invoke ansible docker "
    "kubernetes google-auth oauthlib requests-oauthlib pyjwt cffi pycparser bcrypt pynacl "
    "passlib python-dotenv marshmallow jsonschema more-itertools grpcio opentelemetry-api "
    "elasticsearch prometheus-client sentry-sdk boltons "
    # ── npm 头部 ──
    "lodash react react-dom axios express chalk commander debug moment webpack typescript "
    "eslint prettier jest mocha chai vue rxjs redux next nuxt jquery bootstrap tailwindcss "
    "postcss autoprefixer dotenv cors body-parser mongoose sequelize mysql2 node-fetch "
    "cross-env rimraf glob minimist yargs inquirer semver uuid nanoid classnames "
    "styled-components formik yup zod immer dayjs date-fns ramda underscore markdown-it "
    "socket.io vite rollup esbuild babel-core core-js knex"
)
_POPULAR_PACKAGES: frozenset[str] = frozenset(_normalize_pkg(n) for n in _POPULAR_RAW.split())


def _osa_distance(a: str, b: str, max_dist: int = 2) -> int:
    """Optimal String Alignment(Damerau-Levenshtein 限相邻换位)编辑距离,带上界早退。

    相比纯 Levenshtein 多认「相邻两字符换位」为一步(reqeusts↔requests 的 `ue`↔`eu` = 1 步而非 2),
    正是 typosquat 高频形态。距离一旦超过 `max_dist` 即返回 `max_dist+1`(不必算精确值,只用于阈值)。
    """
    la, lb = len(a), len(b)
    if abs(la - lb) > max_dist:
        return max_dist + 1
    prev2: list[int] = []
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        row_min = cur[0]
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
            row_min = min(row_min, cur[j])
        if row_min > max_dist:
            return max_dist + 1
        prev2, prev = prev, cur
    return prev[lb]


def _typosquat_target(name: str) -> str | None:
    """依赖名疑似 typosquat 时返回被仿冒的知名包名,否则 None。

    护栏(0 FP 导向,均在此收口):
    - npm scoped 名(`@scope/pkg`、含 `/`)属命名空间/依赖混淆面,不在 typosquat 判定内 → None;
    - 归一化后本身即知名包(含大小写/分隔符变体)→ None(安全,非抢注);
    - 归一名过短(<4)不判(短名编辑距离噪声大);
    - dist==1 需目标名长度 ≥4;dist==2 仅当目标名长度 ≥7 才判(长名才容双编辑,压短名误报)。
    """
    raw = name.strip()
    if not raw or raw.startswith("@") or "/" in raw:
        return None
    norm = _normalize_pkg(raw)
    if len(norm) < 4 or norm in _POPULAR_PACKAGES:
        return None
    best: str | None = None
    best_d = 3
    for pop in _POPULAR_PACKAGES:
        if abs(len(pop) - len(norm)) > 2:
            continue
        d = _osa_distance(norm, pop, 2)
        if d < 1 or d >= best_d:
            continue
        if (d == 1 and len(pop) >= 4) or (d == 2 and len(pop) >= 7):
            best, best_d = pop, d
    return best


def _nested_descriptions(manifest: dict) -> list[str]:
    """抽取嵌套工具/能力的描述文本(`tools:[{name,desc}]` 等),供描述/注入面扫描。

    rug-pull / 描述投毒常把恶意指令藏进**子工具**的 desc(非顶层 description),旧扫描只看顶层
    会漏(如 sc-09)。"""
    out: list[str] = []
    for container in ("tools", "functions", "skills", "commands", "actions"):
        node = manifest.get(container)
        if not isinstance(node, list):
            continue
        for item in node:
            if isinstance(item, dict):
                text = item.get("desc") or item.get("description") or ""
                if str(text).strip():
                    out.append(str(text))
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
            # 通配=元权限(对抗实测 2026-09-04):`permissions:['*']` 不是又一个待枚举的危险词,
            # 而是声明了**全部能力**——比任何具体危险权限都宽,枚举式匹配对它天然失明。
            if "*" in perm:
                risks.append(
                    _finding(
                        "perm.wildcard",
                        "critical",
                        f"声明通配权限(等同全部能力,须按最宽权限审):{perm}",
                        permission=perm,
                    )
                )
                break  # 一个通配已覆盖全部能力,同清单内不再重复计
            for pattern, kind, severity in _PERM_RULES:
                if pattern.search(perm) and kind not in seen_kinds:
                    seen_kinds.add(kind)
                    risks.append(_finding(kind, severity, f"声明高危权限:{perm}", permission=perm))

        # 2) 描述可疑关键词(含嵌套子工具描述:rug-pull / 描述投毒藏在 tools[].desc)
        nested_desc = _nested_descriptions(manifest)
        description = "\n".join(
            [str(manifest.get("description") or manifest.get("desc") or ""), *nested_desc]
        )
        hits = _regex_hits(_DESC_SUSPICIOUS, description, decode=True)
        if hits:
            risks.append(
                _finding(
                    "desc.suspicious", "critical", f"描述含可疑意图关键词:{hits}", matched=hits
                )
            )

        # 2.5) 指令字段注入(Manifest 注入面):被投毒组件把注入/外泄指挥语藏进
        #      instructions/prompt/system 等字段,装载即污染 agent 上下文。
        instr_parts: list[str] = list(nested_desc)  # 子工具描述也是指令注入面(rug-pull)
        for field in _INSTRUCTION_FIELDS:
            instr_parts.extend(_as_list(manifest.get(field)))
        inj = _regex_hits(_MANIFEST_INJECTION, "\n".join(instr_parts), decode=True)
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
        sens = _regex_hits(_SENSITIVE_ACCESS, sens_surface)
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

        # 4) 依赖来源(兼容 dict{名:版本} / list / 字符串):未版本化 URL 源、版本畸高(依赖混淆)、
        #    依赖名 typosquatting(形近知名包抢注,独立按名判,与源/版本无关)。
        seen_dep_kinds: set[str] = set()
        typosquats: list[str] = []
        for dep_name, spec in _dep_items(manifest):
            # URL/源 既可能在版本位(dict 形 名:'git+…'),也可能整条就是 URL(list 形),两处都查。
            blob = f"{dep_name} {spec}".lower()
            label = f"{dep_name}@{spec}" if spec else dep_name
            target = _typosquat_target(dep_name)
            if target:
                typosquats.append(f"{dep_name}→{target}")
            if (
                "://" in blob
                or "git+" in blob
                or "file:" in blob
                or blob.rstrip().endswith((".tgz", ".tar.gz", ".git"))
            ):
                if "dep.install_from_url" not in seen_dep_kinds:
                    seen_dep_kinds.add("dep.install_from_url")
                    risks.append(
                        _finding(
                            "dep.install_from_url",
                            "high",
                            f"从 URL/源码直接安装依赖(未版本化、可变,rug-pull 载体):{label}",
                            dependency=label,
                        )
                    )
            elif _abnormal_version(spec) and "dep.version_anomaly" not in seen_dep_kinds:
                seen_dep_kinds.add("dep.version_anomaly")
                risks.append(
                    _finding(
                        "dep.version_anomaly",
                        "high",
                        f"依赖版本号畸高,疑依赖混淆抢解析:{label}",
                        dependency=label,
                    )
                )
        if typosquats:
            matched = sorted(set(typosquats))
            risks.append(
                _finding(
                    "dep.typosquat",
                    "high",
                    f"依赖名疑似 typosquatting(形近知名包,需人工核对):{matched}",
                    matched=matched,
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

        # 6) 嵌入式载荷扫描(DDIPE 面):任意字段代码块/配置模板里的危险载荷,独立 embedded.* kinds。
        risks.extend(scan_embedded(manifest, ctx))

        rating = self._rating(risks)
        return ScanReport(component_id=component_id, rating=rating, risks=risks)

    @staticmethod
    def _rating(risks: list[Finding]) -> Disposition:
        if not risks:
            return Disposition.ALLOW
        worst = max(risks, key=lambda f: _SEV_RANK.get(str(f.evidence.get("severity")), 0))
        return _RATING_BY_SEV.get(str(worst.evidence.get("severity")), Disposition.ALLOW)
