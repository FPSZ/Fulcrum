"""请求路径上的 manifest 哨兵 —— 把"组件/插件/Skill 清单评估"作为一种输入类型路由到扫描器。

定位:补 corpus 差距报告 §3 P1#9。`manifest_scanner` 是**组件登记/上线的离线**关切
(`python -m fulcrum.scan`),不在每请求管线里;于是供应链类输入此前只过 `keyword_rules`
(语法规则),召回仅 ~27%。本检测器把"请帮我评估这个插件清单:{…}"这类请求识别出来,
抽取并解析其中的 manifest,**复用 `ManifestScanner` 做同一套静态评级**,在入口闸门即给出
分级处置——让"装载即投毒"的组件在被采纳前就被拦/送审。

与 `manifest_scanner` 的分工:扫描器是**评估引擎**(吃 dict 出 ScanReport),本检测器是
**请求路径适配器**(从自由文本里认出 manifest 请求 → 抽取 → 解析 → 交给扫描器 → 把评级
映射成入口闸门分数)。不改扫描器一行,故扫描器的检测覆盖怎么长,这里自动跟着受益。

触发收紧:只有解析出的对象**确是 manifest**(含 name + 至少一项 manifest 信号字段:权限/
钩子/端点/依赖/描述/指令)才出分,避免把任意 `{…}` 误当组件清单(防 FPR 回归)。
"""

from __future__ import annotations

import json
import re

from ...core.domain import Context, Finding, SourceSpan
from ...core.registry import capability
from ..supplychain.manifest_scanner import ManifestScanner

# manifest 信号字段:解析出的 dict 必须含 name + 至少一项,才认定是"组件清单"(否则不出分)。
_MANIFEST_SIGNAL_KEYS: frozenset[str] = frozenset(
    {
        "permissions",
        "scopes",
        "capabilities",
        "hooks",
        "scripts",
        "lifecycle",
        "endpoints",
        "urls",
        "hosts",
        "outbound",
        "dependencies",
        "deps",
        "requires",
        "description",
        "desc",
        "instructions",
        "instruction",
        "prompt",
        "system_prompt",
        "system",
        "tools",
        "commands",
        "actions",
        "functions",
    }
)
# 结构性强信号键:即便缺 name 也足以认定是组件清单(真实依赖/工具清单常以 deps 字典或
# tools 数组直接呈现、不带顶层 name)。语料核验:无任何非供应链良性输入含这些键 → 放宽安全。
_STRONG_SIGNAL_KEYS: frozenset[str] = frozenset(
    {
        "permissions",
        "scopes",
        "capabilities",
        "hooks",
        "scripts",
        "lifecycle",
        "dependencies",
        "deps",
        "requires",
        "endpoints",
        "outbound",
        "tools",
        "commands",
        "actions",
        "functions",
    }
)

# 请求路径处置 = 按风险**性质**分级,而非照搬离线扫描器的最严重级评级:
#   主动恶意载荷(安装钩子执行 / 后门挖矿等描述 / 指令字段注入 / 指名窃取敏感凭据)→
#     装载即危害,入口拦截;
#   仅"声明"可疑(过宽权限 / 可疑端点 / 从 URL 装依赖 / 生命周期钩子)→ 尚未发作,送人工复核。
# 这与 corpus 校准一致:声明吓人 ≠ 已作恶,前者 approve、后者 block。
_ACTIVE_MALICE_KINDS: frozenset[str] = frozenset(
    {
        "hook.install_exec",
        "desc.suspicious",
        "manifest.prompt_injection",
        "sensitive_file_access",
        "manifest.tool_poisoning",
    }
)
_BLOCK_SCORE = 0.9  # → 入口闸门 block(BLOCK_AT=0.8)
_REVIEW_SCORE = 0.7  # → 入口闸门 approve(REVIEW_AT=0.6)


def _extract_braced(text: str) -> str | None:
    """抽取最外层平衡 `{…}` 块(manifest 常嵌在中文请求与【插件清单】标记之间)。"""
    start = text.find("{")
    if start < 0:
        return None
    depth = 0
    for i in range(start, len(text)):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def _loads_lenient(blob: str) -> dict | None:
    """把 JS 对象风格的 manifest(裸键 + 单引号)宽松解析为 dict。

    样例形如 `{name:'x', hooks:{postinstall:'curl … | bash'}}`:先给裸键补引号、单引号
    转双引号再 `json.loads`;严格 JSON 直接成功。解析失败或非 dict → None(不出分)。
    """
    for candidate in (blob, _jsonify(blob)):
        try:
            obj = json.loads(candidate)
        except (ValueError, TypeError):
            continue
        if isinstance(obj, dict):
            return obj
    return None


def _jsonify(blob: str) -> str:
    quoted_keys = re.sub(r"([{,]\s*)([A-Za-z_][\w]*)\s*:", r'\1"\2":', blob)
    return quoted_keys.replace("'", '"')


def _looks_like_manifest(obj: dict) -> bool:
    # name + 任一信号字段;或缺 name 但含结构性强信号键(依赖字典 / 工具数组等)。
    if "name" in obj and any(k in obj for k in _MANIFEST_SIGNAL_KEYS):
        return True
    return any(k in obj for k in _STRONG_SIGNAL_KEYS)


@capability("detector", "manifest_guard")
class ManifestGuardDetector:
    """请求路径 manifest 哨兵:认出组件清单评估请求 → 抽取解析 → 交扫描器分级处置。"""

    name = "manifest_guard"

    def __init__(self) -> None:
        self._scanner = ManifestScanner()

    def detect(self, spans: list[SourceSpan], ctx: Context) -> list[Finding]:
        findings: list[Finding] = []
        for span in spans:
            blob = _extract_braced(span.excerpt)
            if not blob:
                continue
            manifest = _loads_lenient(blob)
            if manifest is None or not _looks_like_manifest(manifest):
                continue
            report = self._scanner.scan(manifest, ctx)
            if not report.risks:
                continue  # 干净 manifest → 不出分(放行)
            risk_kinds = sorted({str(f.kind) for f in report.risks})
            active = bool(_ACTIVE_MALICE_KINDS.intersection(risk_kinds))
            score = _BLOCK_SCORE if active else _REVIEW_SCORE
            findings.append(
                Finding(
                    kind="supplychain_manifest",
                    score=score,
                    evidence={
                        "source_id": span.source_id,
                        "source_type": span.source_type,
                        "trust_level": span.trust_level,
                        "component_id": report.component_id,
                        "scanner_rating": report.rating.value,
                        "disposition": "block" if active else "approve",
                        "active_malice": active,
                        "risk_kinds": risk_kinds,
                    },
                )
            )
        return findings
