"""供应链静态评测:对脱敏 manifest/安装脚本样例跑离线扫描并汇总结果。

此模块只调用组件登记/上线阶段的 ``fulcrum.scan`` 逻辑,不进入请求安全管线,也不执行
manifest 中声明的任何脚本或组件代码。
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field

from ..scan import load_manifest, scan_manifest

_ACTIONS = frozenset({"allow", "sanitize", "approve", "block"})
_HELD = frozenset({"sanitize", "approve", "block"})


class SupplychainEvalSample(BaseModel):
    """一个受控组件样例的离线扫描金标准。``manifest`` 相对标注索引所在目录。"""

    sample_id: str
    manifest: str
    ground_truth_malicious: bool
    expected_action: str
    notes: str = ""


class SupplychainEvidence(BaseModel):
    """报告中保留的静态扫描证据,与 ``ScanReport`` finding 一一对应。"""

    kind: str
    score: float
    severity: str = ""
    detail: str = ""


class SupplychainEvalResult(BaseModel):
    """一条组件样例的实际评级与证据。"""

    sample_id: str
    manifest: str
    malicious: bool
    expected_action: str
    predicted_action: str
    evidence: list[SupplychainEvidence] = Field(default_factory=list)

    @property
    def held(self) -> bool:
        return self.predicted_action in _HELD

    @property
    def decision_correct(self) -> bool:
        return self.predicted_action == self.expected_action


def load_supplychain_dataset(path: str | Path) -> list[SupplychainEvalSample]:
    """读取供应链静态评测索引(JSON 数组),并校验其评级金标准。"""
    index = Path(path)
    if not index.is_file():
        raise FileNotFoundError(f"供应链评测索引不存在:{index}")
    try:
        data = json.loads(index.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"供应链评测索引 JSON 非法:{index}") from exc
    if not isinstance(data, list) or not data:
        raise ValueError(f"供应链评测索引应为非空 JSON 数组:{index}")

    samples: list[SupplychainEvalSample] = []
    seen: set[str] = set()
    for position, item in enumerate(data, 1):
        try:
            sample = SupplychainEvalSample.model_validate(item)
        except Exception as exc:  # noqa: BLE001 - 错误必须指明标注位置
            raise ValueError(f"供应链评测索引 {index} 第 {position} 项无效:{exc}") from exc
        if sample.sample_id in seen:
            raise ValueError(f"供应链评测 sample_id 重复:{sample.sample_id!r}")
        if sample.expected_action not in _ACTIONS:
            raise ValueError(
                f"供应链评测样例 {sample.sample_id!r} 的 expected_action 非法:"
                f"{sample.expected_action!r}"
            )
        manifest_path = index.parent / sample.manifest
        if not manifest_path.is_file():
            raise FileNotFoundError(
                f"供应链评测样例 {sample.sample_id!r} 的 manifest 不存在:{manifest_path}"
            )
        seen.add(sample.sample_id)
        samples.append(sample)
    return samples


def run_supplychain_dataset(
    samples: list[SupplychainEvalSample], index_path: str | Path
) -> list[SupplychainEvalResult]:
    """顺序静态扫描全部受控组件;只读取 manifest,绝不执行其中的 hooks/脚本。"""
    base = Path(index_path).parent
    results: list[SupplychainEvalResult] = []
    for sample in samples:
        manifest_path = base / sample.manifest
        report = scan_manifest(load_manifest(manifest_path))
        evidence = [
            SupplychainEvidence(
                kind=finding.kind,
                score=finding.score,
                severity=str(finding.evidence.get("severity", "")),
                detail=str(finding.evidence.get("detail", "")),
            )
            for finding in sorted(report.risks, key=lambda finding: -finding.score)
        ]
        results.append(
            SupplychainEvalResult(
                sample_id=sample.sample_id,
                manifest=sample.manifest,
                malicious=sample.ground_truth_malicious,
                expected_action=sample.expected_action,
                predicted_action=report.rating.value,
                evidence=evidence,
            )
        )
    return results


def compute_supplychain_metrics(results: list[SupplychainEvalResult]) -> dict:
    """供应链静态扫描的召回、FPR 与评级处置准确率(独立于请求链路指标)。"""
    malicious = [result for result in results if result.malicious]
    benign = [result for result in results if not result.malicious]
    tp = sum(1 for result in malicious if result.held)
    fn = len(malicious) - tp
    fp = sum(1 for result in benign if result.held)
    tn = len(benign) - fp
    return {
        "scope": "offline_static_scan",
        "totals": {
            "samples": len(results),
            "malicious": len(malicious),
            "benign": len(benign),
            "tp": tp,
            "fn": fn,
            "fp": fp,
            "tn": tn,
        },
        "recall": tp / len(malicious) if malicious else 0.0,
        "fpr": fp / len(benign) if benign else 0.0,
        "disposition_accuracy": (
            sum(1 for result in results if result.decision_correct) / len(results)
            if results
            else 0.0
        ),
    }
