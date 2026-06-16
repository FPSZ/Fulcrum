"""评测样例 schema 与加载 —— 对齐 [指标体系 §3.2] 的标注字段(取 MVP 可算子集)。

样例集为 JSONL(每行一条 JSON 对象),脱敏存放于 `samples/eval/`。路由约定:
- 带 `target_tool` → **工具级**样例,过 `evaluate_intent`(策略判定);
- 否则 → **输入级**样例,过 `screen_input`(输入闸门:检测→拦截/审核/放行)。
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field

# 输入级闸门 / 工具级策略都用统一处置词:allow / sanitize / approve / block。
_ACTIONS = frozenset({"allow", "sanitize", "approve", "block"})


class EvalSample(BaseModel):
    """一条评测样例(标注金标准)。字段对齐指标体系 §3.2 的可算子集。"""

    sample_id: str
    scenario: str = "govoffice"
    attack_type: str  # direct_prompt_injection / indirect_injection / jailbreak /
    #                   knowledge_poisoning / unauthorized_tool / benign
    input: str | None = None  # 输入级样例的用户消息
    target_tool: str | None = None  # 工具级样例的目标工具(置位则走 evaluate_intent)
    tool_args: dict = Field(default_factory=dict)
    source_type: str = "user"
    ground_truth_malicious: bool = False
    expected_action: str = "allow"  # 期望处置(allow/sanitize/approve/block)
    expected_trace_source: str | None = None
    notes: str = ""

    @property
    def is_tool_sample(self) -> bool:
        return self.target_tool is not None


def load_dataset(path: str | Path) -> list[EvalSample]:
    """读取 JSONL 样例集;逐行校验,空行跳过。期望处置取值非法即报错(防标注笔误)。"""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"样例集不存在:{p}")
    samples: list[EvalSample] = []
    for lineno, raw in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            sample = EvalSample.model_validate(json.loads(line))
        except Exception as exc:  # noqa: BLE001 —— 标注错误要带行号明确报出
            raise ValueError(f"样例集第 {lineno} 行解析失败:{exc}") from exc
        if sample.expected_action not in _ACTIONS:
            raise ValueError(
                f"样例 {sample.sample_id!r} 的 expected_action 非法:{sample.expected_action!r}"
            )
        samples.append(sample)
    if not samples:
        raise ValueError(f"样例集为空:{p}")
    return samples
