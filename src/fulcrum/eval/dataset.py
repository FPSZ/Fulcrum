"""评测样例 schema 与加载 —— 对齐 [指标体系 §3.2] 的标注字段(取 MVP 可算子集)。

样例集为 JSONL(每行一条 JSON 对象),脱敏存放于 `samples/eval/`。路由约定(优先级从高到低):
- 带 `target_tool` → **工具级**样例,过 `evaluate_intent`(策略判定);
- 带 `reply` → **出口级**样例,过 `screen_output`(出口闸门:检测→放行/脱敏/复核/拦截),
  用于量化「响应后检查模型输出」的防泄露目标(01 §4.2);
- 否则 → **输入级**样例,过 `screen_input`(输入闸门:检测→拦截/审核/放行)。

`--dataset` 既可指向单个 JSONL,也可指向**目录**(攻击样例库 `samples/eval/corpus/`):
目录递归收集全部 `*.jsonl`(下划线开头的文件跳过,留作索引/草稿),逐行校验并合并,
sample_id 全局去重(撞号即报错,防复制粘贴漏改)。Schema/分类规范见 `corpus/SPEC.md`。
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field

# 输入级闸门 / 工具级策略都用统一处置词:allow / sanitize / approve / block。
_ACTIONS = frozenset({"allow", "sanitize", "approve", "block"})


class EvalSample(BaseModel):
    """一条评测样例(标注金标准)。字段对齐指标体系 §3.2 + 标准化分类元数据(SPEC.md)。"""

    sample_id: str
    scenario: str = "govoffice"
    attack_type: str  # direct_prompt_injection / indirect_injection / jailbreak /
    #                   knowledge_poisoning / unauthorized_tool / data_exfiltration /
    #                   data_leak / data_poisoning / supply_chain / benign
    input: str | None = None  # 输入级样例的用户消息
    reply: str | None = None  # 出口级样例:企业智能体的回复(置位则走 screen_output)
    target_tool: str | None = None  # 工具级样例的目标工具(置位则走 evaluate_intent)
    tool_args: dict = Field(default_factory=dict)
    source_type: str = "user"
    ground_truth_malicious: bool = False
    expected_action: str = "allow"  # 期望处置(allow/sanitize/approve/block)
    expected_trace_source: str | None = None
    notes: str = ""
    # —— 标准化分类元数据(可选;对齐 OWASP/MITRE/CWE,见 corpus/SPEC.md + TAXONOMY.md)——
    technique: str = ""  # 细分手法 slug,如 "ssrf.cloud_metadata.aliyun"
    owasp: str = ""  # OWASP LLM Top10:2025,如 "LLM01:2025"
    mitre_atlas: str = ""  # MITRE ATLAS 技术,如 "AML.T0051.001"
    mitre_attack: str = ""  # MITRE ATT&CK 技术,如 "T1059.001"
    cwe: str = ""  # CWE 编号,如 "CWE-1427"
    severity: str = ""  # critical / high / medium / low(见 SPEC.md 严重度评级)
    source: str = "self"  # 来源:self 自建 / upstream:<repo> 情报源
    version_added: str = ""  # 入库版本(SemVer),如 "1.0.0"
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    @property
    def is_tool_sample(self) -> bool:
        return self.target_tool is not None

    @property
    def is_output_sample(self) -> bool:
        """出口级样例:有回复待出口检测、且非工具级(工具级优先)。"""
        return self.reply is not None and self.target_tool is None


def _parse_line(raw: str, lineno: int, where: Path) -> EvalSample | None:
    """解析单行;空行/注释返回 None。校验失败带文件名+行号报出。"""
    line = raw.strip()
    if not line or line.startswith("#"):
        return None
    try:
        sample = EvalSample.model_validate(json.loads(line))
    except Exception as exc:  # noqa: BLE001 —— 标注错误要带行号明确报出
        raise ValueError(f"{where} 第 {lineno} 行解析失败:{exc}") from exc
    if sample.expected_action not in _ACTIONS:
        raise ValueError(
            f"{where} 样例 {sample.sample_id!r} 的 expected_action 非法:{sample.expected_action!r}"
        )
    return sample


def _iter_files(path: Path) -> list[Path]:
    """单文件原样返回;目录则递归收集 *.jsonl(跳过下划线开头),按路径排序。"""
    if path.is_dir():
        return sorted(p for p in path.rglob("*.jsonl") if not p.name.startswith("_"))
    return [path]


def load_dataset(path: str | Path) -> list[EvalSample]:
    """读取 JSONL 样例集(单文件或目录);逐行校验,空行/注释跳过,sample_id 全局去重。"""
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"样例集不存在:{root}")
    files = _iter_files(root)
    if not files:
        raise ValueError(f"目录下无 *.jsonl 样例文件:{root}")
    samples: list[EvalSample] = []
    seen: dict[str, Path] = {}
    for f in files:
        for lineno, raw in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            sample = _parse_line(raw, lineno, f)
            if sample is None:
                continue
            if sample.sample_id in seen:
                raise ValueError(
                    f"sample_id 重复:{sample.sample_id!r} 同时见于 {seen[sample.sample_id]} 与 {f}"
                )
            seen[sample.sample_id] = f
            samples.append(sample)
    if not samples:
        raise ValueError(f"样例集为空:{root}")
    return samples
