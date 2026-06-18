"""MlClassifierDetector —— 神经语义注入检测(P6 语义兜底层,对应赛题目标①)。

确定性规则(keyword_rules)抓"措辞/特征",对**语义改写**的注入/越狱有天花板:doc 09 实测
规则法总召回 ~71%,改头换面、不含已知关键词的语义注入抓不到。本检测器接 HuggingFace
提示注入分类器(默认 protectai/deberta-v3-base-prompt-injection-v2)做**语义兜底**,与规则
分数融合:规则做"快速精准前置",神经做"语义召回兜底"。

**融合策略(关键,防 FPR 灾难)**:专用分类器单跑召回高但 FPR 灾难(protectai 标准阈下
FPR~47%,doc 08 §9)。故本层:① 阈值默认取高(0.9,只认高置信攻击);② ML 单独贡献**封顶
max_score=0.7** —— ML 独自最多把请求升到"复核(人工)",**不凭 ML 单独自动拦截**;唯有规则
也命中时综合才达拦截。既借神经补召回,又用规则+信任+封顶守住 FPR。

**可选重依赖 + 缺失自动降级(诚实声明)**:transformers/torch **懒加载**;装不上 / 模型不可达
→ 本检测器降级为 no-op(返回 []),能力照常注册,**绝不拖垮确定性规则基线**(规则仍是
fail-closed 底座)。单次推理异常同样降级跳过、不上抛——ML 是**叠加增益**,其缺失/故障不得
反而拦截一切。故本检测器对自身故障 fail-safe,而非 fail-closed(底座的 fail-closed 不依赖它)。

**默认不入装配**:重依赖、需独立 ML 环境(本仓 uv venv 无 ML 栈,见 doc 08 §10)。已注册进
registry,在装好 transformers/torch 的环境里于 fulcrum.yml `detectors` 启用即可,默认管线零改动。
"""

from __future__ import annotations

import importlib
import logging
from collections.abc import Callable

from ...core.domain import Context, Finding, SourceSpan, TrustLevel
from ...core.registry import capability

_LOG = logging.getLogger(__name__)

# 默认分类器:基准已横评、经 hf-mirror 可拉(doc 08 §10 E)。
_DEFAULT_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"
# 判为"攻击"的标签(不同分类器标签名不一,统一大写后比对)。
_ATTACK_LABELS: frozenset[str] = frozenset({"INJECTION", "JAILBREAK", "MALICIOUS", "LABEL_1"})

# 来源信任级 -> 乘子(与 keyword_rules 同口径,保证融合数学一致)。
_TRUST_MUL: dict[TrustLevel, float] = {
    TrustLevel.UNTRUSTED: 1.0,
    TrustLevel.SEMI_TRUSTED: 0.8,
    TrustLevel.TRUSTED: 0.55,
}


def _severity(score: float) -> str:
    if score >= 0.8:
        return "critical"
    if score >= 0.6:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"


def _load_default_backend(model: str, device: int | str | None) -> Callable[[str], float]:
    """构建默认 HF 文本分类后端:(text) -> 攻击概率[0,1]。

    用 importlib 动态导入 transformers(未安装即抛 ImportError,由调用方降级处理)。
    """
    transformers = importlib.import_module("transformers")
    kwargs: dict = {"truncation": True, "max_length": 512}
    if device is not None:
        kwargs["device"] = device
    clf = transformers.pipeline("text-classification", model=model, **kwargs)

    def score(text: str) -> float:
        out = clf(text)[0]
        label = str(out["label"]).upper()
        prob = float(out["score"])
        # 顶标签是攻击 → 用其概率;是良性 → 攻击概率取补。
        return prob if label in _ATTACK_LABELS else 1.0 - prob

    return score


@capability("detector", "ml_classifier")
class MlClassifierDetector:
    """神经语义注入检测器。注册名 `ml_classifier`;装好 ML 栈后在 fulcrum.yml 启用。

    backend 可注入((text)->攻击概率)以便确定性测试;为 None 时惰性加载默认 HF 后端。
    """

    name = "ml_classifier"

    def __init__(
        self,
        model: str = _DEFAULT_MODEL,
        threshold: float = 0.9,
        max_score: float = 0.7,
        max_chars: int = 4000,
        device: int | str | None = None,
        backend: Callable[[str], float] | None = None,
    ) -> None:
        self._model = model
        self._threshold = float(threshold)  # 只认高置信攻击,压低 FPR
        self._max_score = float(max_score)  # ML 单独贡献封顶(独自最多升到复核,不自动拦截)
        self._max_chars = int(max_chars)
        self._device = device
        self._backend = backend
        self._tried_load = backend is not None  # 已注入则无需再加载
        self._degraded = False

    def _ensure_backend(self) -> None:
        """首次使用时惰性加载默认后端;失败则降级(no-op),只告警一次。"""
        if self._backend is not None or self._degraded or self._tried_load:
            return
        self._tried_load = True
        try:
            self._backend = _load_default_backend(self._model, self._device)
        except Exception as exc:  # noqa: BLE001 —— 缺 ML 栈/模型不可达 → 降级,不拖垮规则基线
            self._degraded = True
            _LOG.warning("ml_classifier 降级(语义检测未启用):%s", exc)

    def detect(self, spans: list[SourceSpan], ctx: Context) -> list[Finding]:
        self._ensure_backend()
        if self._backend is None:  # 降级:确定性规则仍在,ML 仅作可选增益
            return []
        findings: list[Finding] = []
        for span in spans:
            text = span.excerpt[: self._max_chars]
            if not text.strip():
                continue
            try:
                prob = float(self._backend(text))
            except Exception as exc:  # noqa: BLE001 —— 单次推理异常 → 跳过该 span(降级),不拦全部
                _LOG.warning("ml_classifier 推理异常,跳过该 span:%s", exc)
                continue
            if prob < self._threshold:
                continue
            trust_mul = _TRUST_MUL.get(span.trust_level, 1.0)
            score = round(min(prob, self._max_score) * trust_mul, 3)
            findings.append(
                Finding(
                    kind="ml_injection",
                    score=score,
                    evidence={
                        "source_id": span.source_id,
                        "source_type": span.source_type,
                        "trust_level": span.trust_level,
                        "severity": _severity(score),
                        "ml_prob": round(prob, 3),
                        "model": self._model,
                        "threshold": self._threshold,
                    },
                )
            )
        return findings
