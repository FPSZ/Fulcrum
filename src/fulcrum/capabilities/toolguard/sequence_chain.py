"""SequenceChainAnalyzer —— 任务链 / 轨迹异常检测,对应赛题目标②。

单个工具调用可能各自合规(读一份文件、向白名单域发一次请求),但**特定顺序的组合**才是
攻击:最典型的「敏感数据读取 → 对外发送」数据外泄链。本分析器在**请求级**动作序列(trace)
上做有序模式匹配,对当前(最新)调用判断它是否构成异常链的"收口动作",产出带置信度的
Finding,交由策略据 `chain_risk_at_least` 分级处置(读取后外发 → 审批;敏感读取后外发 → 阻断)。

确定性、可解释:动作按工具名 + 参数归类(读取 / 外发),复用 argrisk 的敏感路径判定。
窗口暂以"最近 N 步"近似(ToolIntent 尚无时间戳),N 见 `_WINDOW`。
`trace` 是**请求级**序列(见 Context 生命周期说明);跨请求链待 SessionStore port,本实现不涉及。
Finding 的 evidence 带 `intent_id`(= 触发链的当前调用),供策略只对"当前这步"判链,避免误伤。

接口为 async(与 ChainAnalyzer port 一致,为终局接向量库/模型留空间);当前实现纯本地、无 await。
"""

from __future__ import annotations

import base64
import binascii
import re

from ...core.domain import Context, Finding, ToolIntent
from ...core.registry import capability
from . import argrisk

# 动作归类:对工具名做关键词匹配(中英)。
_READ_RE = re.compile(
    r"(read|search|query|fetch|get|list|load|select|读取|查询|检索)", re.IGNORECASE
)
_EXFIL_RE = re.compile(
    r"(send|post|upload|forward|external|http|webhook|email|notify|exfil|sync|push|外发|外传|上传|发送)",
    re.IGNORECASE,
)
# 敏感数据读取(按工具名,补充 argrisk 的敏感路径判定)。
_SENSITIVE_RE = re.compile(
    r"(citizen|personal|secret|credential|confidential|ledger|roster|个人|公民|台账|花名册|凭据|涉密|机密)",
    re.IGNORECASE,
)
# 外发动作的目的地参数键:即便工具名未命中,带这些参数也视为对外动作。
_DEST_KEYS = frozenset(
    {
        "url",
        "to",
        "recipient",
        "recipients",
        "dest",
        "destination",
        "email",
        "endpoint",
        "webhook",
        "target",
        "address",
    }
)
# 持久化/长期存储 sink:记忆、知识库、长期事实库。把不可信工具返回原样写进这里 = 记忆投毒,
# 影响未来所有会话的决策。与"对外发送"并列,是任务链的另一类收口动作。
_PERSIST_RE = re.compile(
    r"(remember|memor(y|ize)|recall|persist|knowledge|\bkb\b|长期|记忆|记住|知识库)",
    re.IGNORECASE,
)
# 通用写动作动词(工具名未直说记忆/知识库时,配合目标路径/键判断写入 sink 性质)。
_WRITE_RE = re.compile(
    r"(write|save|store|append|update|upsert|put|记录|写入|保存|存储)", re.IGNORECASE
)
# 承载写入内容的参数键:持久化写入须带内容才有"投毒"意义。
_CONTENT_KEYS = frozenset({"content", "value", "text", "data", "body", "fact", "note", "memory"})
# 执行收口:工具名命中执行类动词,或带承载命令/脚本的参数键。收紧到"执行"语义 ——
# query/fetch/read 是链的「获取」段而非「执行」段,绝不纳入(eval/run/code 用词边界框死,
# 不误吃 evaluate/pruner/decode 之类)。仅判 sink 性质,是否报由跨步关联(下方)硬门控。
_EXECUTE_RE = re.compile(
    r"(exec|\brun\b|\beval\b|spawn|subprocess|shell|interpret|\bcode\b|执行|运行)",
    re.IGNORECASE,
)
# 承载待执行命令/脚本的参数键(与 shell.exec={command}、code.run={code} 等工具形态对齐)。
_EXEC_ARG_KEYS = ("command", "cmd", "script", "code")
# 回看窗口(步数近似)。当前调用之前的 _WINDOW 步内出现敏感/普通读取即构成链。
_WINDOW = 12
# 跨步污点:外发参数里出现长度 ≥ 此阈值、源自某一步工具返回的连续片段 → 判定污点。
# 阈值取得够长以避免短公共串(如 "true"/url 协议头)误报。
_TAINT_MIN = 12
# write→execute 路径关联的最小路径长度:路径须含分隔符且达此量级,避免裸文件名 / 短串
# (如 "/" 或 "a.sh")在命令里偶然命中。比 _TAINT_MIN 略松 —— 带分隔符的路径本身已具判别力。
_PATH_MIN = 6
# 内联代码执行位引导符:其后的文本被解释器**当代码执行**(而非数据参数)——
# `python -c <src>`、`bash -c`、`perl -e`、`php -r`、`pwsh -Command`、`eval`/`exec`/`source <src>`。
# 用于把内联污点的执行位判别从"命令里任意出现"收窄到"确实落在被执行的源码段"。
_INLINE_CODE_INTRO = re.compile(
    r"\b(?:eval|exec|source)\b\s"
    r"|\b(?:python[0-9.]*|perl|ruby|php|node(?:js)?|deno|bun|(?:ba|z|da|k|a)?sh|pwsh|powershell)\b"
    r"[^|;&\n]*?\s-(?:c|e|r|command|encodedcommand)\b\s",
    re.IGNORECASE,
)
# 管道喂解释器:`<payload> | sh`/`| bash`/`| python` —— 管道左侧内容被 shell/解释器执行。
_PIPE_TO_SHELL = re.compile(
    r"\|\s*(?:(?:ba|z|da|k|a)?sh|python[0-9.]*|perl|ruby|node(?:js)?|pwsh|powershell)\b",
    re.IGNORECASE,
)

# 编码外发规避:把上一步读到的敏感量先 Base64/Hex 编码再外发,可绕过原样子串比对。
# 故对外发参数里的编码块就地解码,得到的明文一并参与污点比对。阈值取够长以避免噪声:
# Base64 ≥16 字符(≥12 字节明文)、Hex ≥24 字符(≥12 字节明文),均对齐 _TAINT_MIN。
_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_BLOB = re.compile(r"(?:[0-9a-fA-F]{2}){12,}")


def _decoded_variants(text: str) -> list[str]:
    """抽取外发文本里的 Base64/Hex 块并解码为明文(utf-8,无法解码的丢弃)。

    用于堵「编码后外发」规避:`send(data=base64(secret))` 时原文不含 secret 子串,但解码块含。
    确定性:仅解码格式合法且能落地为 utf-8 的块,失败静默跳过,不猜测。
    """
    out: list[str] = []
    for m in _B64_BLOB.finditer(text):
        blob = m.group()
        try:
            dec = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        text_dec = dec.decode("utf-8", "ignore")
        if text_dec:
            out.append(text_dec)
    for m in _HEX_BLOB.finditer(text):
        try:
            dec = bytes.fromhex(m.group())
        except ValueError:
            continue
        text_dec = dec.decode("utf-8", "ignore")
        if text_dec:
            out.append(text_dec)
    return out


def _args_text(intent: ToolIntent) -> str:
    """外发动作的参数值拼成可比对文本(只取值,键名不参与污点比对)。"""
    return " ".join(str(v) for v in intent.arguments.values())


def _normalize_taint(s: str) -> str:
    """污点比对归一化:抹除所有空白 + casefold。

    挫败"原样外发但大小写不同 / 字符间插空格"这类规避;去空白还顺带让被空格拆进多个
    参数字段的连续敏感量在拼接文本里重新相邻,缩小分片绕过面。
    """
    return "".join(s.split()).casefold()


def _taint_source(intent: ToolIntent, tool_returns: list[str]) -> tuple[str, bool] | None:
    """当前外发参数是否源自某一步工具返回:取返回内容的连续片段在参数文本里命中即判污点。

    归一化(去空白 + casefold)后做**逐位**滑窗子串匹配 —— 此前以步长 4 跳采会漏掉起点不
    对齐的字面子串(实测 'SECRETDATA99' 原样外发却判 None);步长改 1 并归一化后,对齐 /
    大小写 / 插空格三类规避一并堵死。除原样参数文本外,还把参数里的 Base64/Hex 块解码后
    一并作为比对干草堆,堵「编码后外发」规避。返回 (命中的原始返回内容摘要, 是否经编码),
    无则 None。原样命中优先于编码命中。确定性子串匹配,不猜测。
    """
    return _taint_in_text(_args_text(intent), tool_returns)


def _taint_in_text(haystack_raw: str, tool_returns: list[str]) -> tuple[str, bool] | None:
    """`_taint_source` 的干草堆无关核:判 `haystack_raw`(原样 + 解码块)是否含某一步工具
    返回的连续片段。抽出来供内联污点把比对面**收窄到命令的执行位区域**(见 `_inline_exec_taint`),
    `_taint_source` 仍以"全部参数值文本"为干草堆,行为逐位不变。
    """
    haystacks: list[tuple[str, bool]] = [(_normalize_taint(haystack_raw), False)]
    haystacks += [(_normalize_taint(dec), True) for dec in _decoded_variants(haystack_raw)]
    for ret in tool_returns:
        norm = _normalize_taint(ret)
        if len(norm) < _TAINT_MIN:
            continue
        for hay, encoded in haystacks:
            if len(hay) < _TAINT_MIN:
                continue
            for i in range(len(norm) - _TAINT_MIN + 1):
                if norm[i : i + _TAINT_MIN] in hay:
                    return ret.strip()[:80], encoded
    return None


def _is_read(intent: ToolIntent) -> bool:
    return bool(_READ_RE.search(intent.tool_name))


def _is_outbound(intent: ToolIntent) -> bool:
    if _EXFIL_RE.search(intent.tool_name):
        return True
    return any(k in intent.arguments for k in _DEST_KEYS)


def _is_sensitive_read(intent: ToolIntent) -> bool:
    return _is_read(intent) and (
        argrisk.path_sensitive(intent.arguments) or bool(_SENSITIVE_RE.search(intent.tool_name))
    )


def _persist_target(intent: ToolIntent) -> str:
    return str(
        intent.arguments.get("path")
        or intent.arguments.get("key")
        or intent.arguments.get("target")
        or ""
    )


def _is_persist_write(intent: ToolIntent) -> bool:
    """是否把内容写入长期记忆/知识库等持久化 sink(记忆投毒链的收口动作)。

    两条判别,任一成立即可:
    - 工具名本身就是记忆/知识库交互(memory.*/kb.*/knowledge.*/remember…)且带写入内容;
    - 通用写动作(write/save/append…),但目标路径/键指向记忆/知识库。
    后者把目标限定在持久化 sink,正常 `file.write` 到工作区不误触。
    """
    name = intent.tool_name
    has_content = any(k in intent.arguments for k in _CONTENT_KEYS)
    if _PERSIST_RE.search(name) and has_content:
        return True
    return bool(_WRITE_RE.search(name) and _PERSIST_RE.search(_persist_target(intent)))


def _exec_text(intent: ToolIntent) -> str:
    """取执行动作里承载命令/脚本的文本(按 _EXEC_ARG_KEYS 优先级);无则空串。"""
    for k in _EXEC_ARG_KEYS:
        v = intent.arguments.get(k)
        if v:
            return str(v)
    return ""


def _is_execute(intent: ToolIntent) -> bool:
    """是否为「执行」收口动作(shell.exec / code.run / subprocess… 或带 command/script 参数)。

    第三类收口动作:把抓取/落盘得到的载荷真正跑起来(RCE 暂存链的最后一跳)。收紧到执行语义,
    取数类(query/fetch/read)不纳入。是否产 Finding 仍由 analyze 里的跨步关联硬门控。
    """
    if _EXECUTE_RE.search(intent.tool_name):
        return True
    return any(k in intent.arguments for k in _EXEC_ARG_KEYS)


def _is_file_write(intent: ToolIntent) -> bool:
    """是否为带目标路径的文件写动作(staged 链的「落盘」段)。"""
    return bool(_WRITE_RE.search(intent.tool_name)) and "path" in intent.arguments


def _path_in_command(path: str, exec_norm: str) -> bool:
    """落盘路径是否原文出现在(已归一化的)执行命令文本里。

    路径须含分隔符且达 _PATH_MIN 量级才比对,避免裸文件名 / 短串偶然命中(FP 护栏)。
    这是"是否被引用"的外层门,真正"是否被执行"还需 `_path_executed` 收紧位置。
    """
    if "/" not in path and "\\" not in path:
        return False
    norm = _normalize_taint(path)
    return len(norm) >= _PATH_MIN and norm in exec_norm


def _path_executed(path: str, command: str) -> bool:
    """落盘路径在命令里是否处于**执行位**(被当作程序运行),而非仅作数据参数喂给既有程序。

    暂存链的判别核心:被执行的是"刚落盘的那个文件"。两类执行位:
    - 解释器/加载器后紧跟该路径:`bash /tmp/p.sh`、`python3 /tmp/x.py`、`source ./a.sh`;
    - 该路径作为命令首 token 直接执行(可前置 sudo/env/exec 等):`/tmp/p.sh`、`./run.sh`。
    `python /opt/render.py --in /tmp/data.csv` 里 data.csv 只是 `--in` 的数据值、不在执行位 →
    False,据此堵掉「抓数据→落盘→既有程序读该数据」这类 ETL/绘图良性误报(含其被污点升级)。
    `base64 -d X | sh` 这类"间接执行"不靠本判定,由 argrisk.command_dangerous 单独认定。
    """
    if not path:
        return False
    p = re.escape(path)
    tail = r"(?![\w./\\-])"  # 路径后不接路径字符,避免 /tmp/p 误配 /tmp/print.log
    interp = re.compile(
        r"\b(?:(?:ba|z|da|k|a)?sh|python[0-9.]*|perl|ruby|php|node(?:js)?|pwsh|powershell"
        r"|deno|bun|source)\b\s+(?:-\S+\s+)*[\"']?(?:\.[\\/])?" + p + tail,
        re.IGNORECASE,
    )
    direct = re.compile(
        r"(?:^|[;&|`(]|&&|\|\|)\s*"
        r"(?:(?:sudo|nohup|time|exec|source|command)\s+)*"
        r"(?:env\s+\w+=\S+\s+)*"
        r"[\"']?(?:\.[\\/])?" + p + tail,
        re.IGNORECASE,
    )
    return bool(interp.search(command) or direct.search(command))


def _inline_exec_taint(current: ToolIntent, tool_returns: list[str]) -> tuple[str, bool] | None:
    """内联污点**且处于执行位**才认:把抓到的内容判 critical 的前提是它确实被当**代码执行**,
    而非仅作 `--flag value` / 位置数据参数喂给既有程序。

    对齐分支②的"执行位 vs 数据参数"判别(复审修正):工具返回的长路径/配置串原样出现在
    `python3 /opt/etl/aggregate.py --input <该串>` 里时,旧逻辑无条件判 critical = 误报。
    三类执行位(任一,污点须落在其中)才算:
    - 命令本身危险(`argrisk.command_dangerous`:`python -c`、`|sh`、`base64 -d|sh`、`curl|bash`…)
      → 内联污点必在执行语境,沿用原判定;
    - 污点落在内联解释器源码段(`-c/-e/-r/eval/exec/source` 之后)或管道喂 shell 的左侧;
    - 命令以抓取内容打头(整条命令 / 首 token 即被执行的程序本身)。
    真内联脚本执行(`python3 -c "<抓取脚本>"`、整条命令即抓取脚本)仍 critical;数据参数不报。
    """
    cmd = _exec_text(current)
    if not cmd or not tool_returns:
        return None
    # ① 命令本身危险:内联污点处于执行语境,沿用原 _taint_source 判定与摘要。
    if argrisk.command_dangerous(current.arguments):
        return _taint_source(current, tool_returns)
    # ② 污点落在执行位区域:内联解释器源码尾 + 管道入 shell 的左侧。
    regions: list[str] = []
    intro = _INLINE_CODE_INTRO.search(cmd)
    if intro:
        regions.append(cmd[intro.end() :])
    pipe = _PIPE_TO_SHELL.search(cmd)
    if pipe:
        regions.append(cmd[: pipe.start()])
    if regions:
        hit = _taint_in_text(" ".join(regions), tool_returns)
        if hit is not None:
            return hit
    # ③ 命令以抓取内容打头:被执行的程序本身即抓取内容(首 token / 整条命令)。
    norm_cmd = _normalize_taint(cmd)
    for ret in tool_returns:
        norm_ret = _normalize_taint(ret)
        if len(norm_ret) >= _TAINT_MIN and norm_cmd.startswith(norm_ret):
            return ret.strip()[:80], False
    return None


@capability("chain_analyzer", "sequence")
class SequenceChainAnalyzer:
    """有序动作链检测。注册名 `sequence`,在 fulcrum.yml 启用。"""

    async def analyze(self, trace: list[ToolIntent], ctx: Context) -> list[Finding]:
        if not trace:
            return []
        current = trace[-1]
        outbound = _is_outbound(current)
        # 收口动作有三类:对外发送(外泄链)、写入长期记忆/知识库(记忆投毒链)、
        # 执行落盘/抓取的载荷(获取→落盘→执行的 RCE 暂存链)。三类互不改动、并列判定。
        if not outbound:
            if _is_persist_write(current):
                return self._persistence_findings(current, ctx)
            if _is_execute(current):
                return self._staged_execution_findings(current, trace, ctx)
            return []

        findings: list[Finding] = []

        # ① 跨步数据流污点:外发参数确实源自上一步工具返回 —— 比"顺序巧合"更硬的外泄证据。
        taint = _taint_source(current, ctx.tool_returns)
        if taint is not None:
            tainted, encoded = taint
            # 编码后外发是更强的恶意信号(刻意隐藏载荷,不可能是顺序巧合),证据再加重。
            pattern = "tool_return->encode->exfil" if encoded else "tool_return->exfil"
            findings.append(
                Finding(
                    kind="chain.taint_exfiltration",
                    score=0.95 if encoded else 0.9,
                    evidence={
                        "intent_id": current.intent_id,
                        "pattern": pattern,
                        "severity": "critical",
                        "exfil_tool": current.tool_name,
                        "tainted_from": tainted,
                        "encoded": encoded,
                    },
                )
            )

        # ② 顺序模式:窗口内出现(敏感)读取 + 当前外发。
        window = trace[-(_WINDOW + 1) : -1]  # 当前调用之前、窗口内的历史调用
        reads = [t for t in window if _is_read(t)]
        if reads:
            sensitive = any(_is_sensitive_read(t) for t in reads)
            score = 0.85 if sensitive else 0.5
            pattern = "sensitive_read->exfil" if sensitive else "read->exfil"
            findings.append(
                Finding(
                    kind="chain.exfiltration",
                    score=score,
                    evidence={
                        "intent_id": current.intent_id,
                        "pattern": pattern,
                        "severity": "critical" if sensitive else "medium",
                        "read_tools": [t.tool_name for t in reads][:3],
                        "exfil_tool": current.tool_name,
                        "window_steps": _WINDOW,
                    },
                )
            )

        return findings

    @staticmethod
    def _persistence_findings(current: ToolIntent, ctx: Context) -> list[Finding]:
        """记忆投毒链:把**源自不可信工具返回**的内容原样写进长期记忆/知识库。

        仅在污点成立(写入内容确实来自上一步工具返回)时收口 —— 把外部内容存进长期库会污染
        未来所有会话的决策,是 AI 推荐投毒 / 持久化记忆投毒的核心动作。评分定在复核档(非硬拦),
        因为「抓取一份正规文档入库」是合法 RAG 流程,语义善恶难由链结构断定,交人工复核更稳妥;
        编码后再写入(刻意隐藏载荷)恶意性更强,评分上调但仍在复核档内。
        """
        taint = _taint_source(current, ctx.tool_returns)
        if taint is None:
            return []
        tainted, encoded = taint
        pattern = "tool_return->encode->persist" if encoded else "tool_return->persist"
        return [
            Finding(
                kind="chain.persistence_poisoning",
                score=0.75 if encoded else 0.6,
                evidence={
                    "intent_id": current.intent_id,
                    "pattern": pattern,
                    "severity": "high",
                    "sink_tool": current.tool_name,
                    "tainted_from": tainted,
                    "encoded": encoded,
                },
            )
        ]

    @staticmethod
    def _staged_execution_findings(
        current: ToolIntent, trace: list[ToolIntent], ctx: Context
    ) -> list[Finding]:
        """获取→落盘→执行(RCE 暂存链)的执行收口判定。

        核心铁律:**没有具体跨步关联就绝不报**。两条硬证据,任一成立才收口:
        - 内联:当前 exec 的命令/脚本文本污点源自上一步工具返回**且处于执行位**(模型把抓到的
          脚本直接内联进 shell.exec,见 `_inline_exec_taint`;仅作 --flag 数据参数不算)→
          tool_return->execute、critical;
        - 路径关联:窗口内某 file.write 步的目标路径被当前命令引用,**且处于执行位**(被当作程序
          运行,见 `_path_executed`)→ write->execute、high。升级 critical 二选一:(a) 该 write 的
          内容污点源自工具返回 → 完整 fetch->write->execute;(b) 当前命令本身危险(curl|bash、
          base64 -d|sh…,此时间接执行,放宽执行位要求)。
        裸 exec("ls")、执行本请求未落盘的既有路径、只写不执行、写与执行路径不相干、落盘文件仅作
        数据参数喂给既有程序(`render.py --in x.csv`)—— 一律 [] 不报。评分落在既有 0.4/0.8 分档
        语义内,经 _chain_risk 泛化自动接策略,policy 零改动。
        """
        exec_text = _exec_text(current)
        if not exec_text:
            return []

        def _build(pattern: str, score: float, **extra: object) -> Finding:
            return Finding(
                kind="chain.staged_execution",
                score=score,
                evidence={
                    "intent_id": current.intent_id,
                    "pattern": pattern,
                    "severity": "critical" if score >= 0.8 else "high",
                    "exec_tool": current.tool_name,
                    **extra,
                },
            )

        # ① 内联:当前命令文本污点源自上一步工具返回**且处于执行位** → 抓到的脚本被内联进执行
        # (最强信号)。执行位判别堵"工具返回长路径/配置当数据参数喂既有程序"的 critical 误报。
        inline = _inline_exec_taint(current, ctx.tool_returns)
        if inline is not None:
            tainted, encoded = inline
            return [_build("tool_return->execute", 0.9, tainted_from=tainted, encoded=encoded)]

        # ② 路径关联:窗口内某 write 步的目标路径被当前命令引用(外层门)。
        exec_norm = _normalize_taint(exec_text)
        window = trace[-(_WINDOW + 1) : -1]
        referenced = [
            w
            for w in window
            if _is_file_write(w) and _path_in_command(str(w.arguments.get("path") or ""), exec_norm)
        ]
        if not referenced:
            return []

        # 铁律收紧:落盘文件须真处于**执行位**(被当作程序运行),否则仅在命令本身危险时才认。
        # 仅作数据参数喂给既有程序(`render.py --in data.csv`)且命令不危险 → 不报(ETL/绘图良性,
        # 含其内容来自工具返回也不误升 critical)。`base64 -d X|sh` 这类间接执行靠 dangerous 兜。
        dangerous = argrisk.command_dangerous(current.arguments)
        executed = [
            w for w in referenced if _path_executed(str(w.arguments.get("path") or ""), exec_text)
        ]
        if not executed and not dangerous:
            return []
        candidates = executed or referenced

        # 升级 critical(a):任一候选 write 的内容污点源自工具返回 → 完整 fetch->write->execute。
        for w in candidates:
            wtaint = _taint_source(w, ctx.tool_returns)
            if wtaint is not None:
                return [
                    _build(
                        "fetch->write->execute",
                        0.9,
                        write_path=str(w.arguments.get("path") or ""),
                        tainted_from=wtaint[0],
                        encoded=wtaint[1],
                    )
                ]

        path0 = str(candidates[0].arguments.get("path") or "")
        # 升级 critical(b):当前命令本身危险(复用 argrisk,不改其口径)且写关联成立。
        if dangerous:
            return [_build("write->execute", 0.9, write_path=path0, dangerous_command=True)]
        return [_build("write->execute", 0.7, write_path=path0)]
