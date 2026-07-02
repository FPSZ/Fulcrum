"""留出集完整性守护(回归 M19)。

只校验数据集**格式与纯良性性质**,不 pin FPR / FP 条目 —— 留出集的价值在"未参与调参",
一旦在测试里断言具体 FP 数,就会诱导有人回头改规则去凑数,重蹈 M19。真实 held-out FPR 见
samples/eval/benchmarks/heldout-benign-fpr.md,由 `python -m fulcrum.eval --dataset ...` 现算。
"""

from __future__ import annotations

from pathlib import Path

from fulcrum.eval.dataset import load_dataset

_HELDOUT = "samples/eval/heldout/benign-heldout.jsonl"


def test_heldout_loads_and_is_all_benign() -> None:
    samples = load_dataset(_HELDOUT)
    assert len(samples) >= 40  # 生成时 40 条,只增不减
    # 留出集必须全良性、金标准全 allow —— 混入任何恶意样本都会污染 FPR 口径。
    for s in samples:
        assert s.ground_truth_malicious is False, f"{s.sample_id} 非良性,不该进留出集"
        assert s.expected_action == "allow", f"{s.sample_id} 金标准应为 allow"


def test_heldout_disjoint_from_inset_benign() -> None:
    """留出集与 in-set 硬负例的 sample_id 不得重叠(否则不算‘未见’)。"""
    heldout_ids = {s.sample_id for s in load_dataset(_HELDOUT)}
    inset = Path("samples/eval/corpus/benign/hard-negatives.jsonl").read_text(encoding="utf-8")
    assert not any(f'"{sid}"' in inset for sid in heldout_ids)
