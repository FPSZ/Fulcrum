"""LLM-judge 语义检测实测 —— 在冻结语料输入子集量 LLM-judge 的召回/FPR,对比规则与专用分类器。

验证 P6 语义层走 LLM-judge(中文原生)而非英文专用分类器:judge 对中文良性咨询近零误报,
融合后保 FPR 补召回。两种后端均经**真 LlmJudgeDetector**测(口径完全一致):
  · 真端点(优先):.env 配 OpenAI 兼容真模型(如 DeepSeek `deepseek-chat`、MiMo)→ 走检测器默认 HTTP 后端。
  · 本地代理(回退):Qwen2.5-1.5B-Instruct(CPU,transformers)注入为后端,无端点也可离线复现。

依赖:真端点模式需 .env(httpx 已是基础依赖);本地代理模式需 transformers/torch(见 doc 08 §10)。
用法:python samples/eval/benchmarks/llm_judge_bench.py
"""

from __future__ import annotations

import json
import math
import os
import sys
import time

sys.path.insert(0, "src")

from fulcrum.capabilities.detectors.keyword_rules import KeywordRuleDetector  # noqa: E402
from fulcrum.capabilities.detectors.llm_judge import _SHOTS, _SYSTEM, LlmJudgeDetector  # noqa: E402
from fulcrum.config import Settings  # noqa: E402
from fulcrum.core.domain import Context, SourceSpan, SourceType, TrustLevel  # noqa: E402
from fulcrum.eval.dataset import load_dataset  # noqa: E402

QWEN = "Qwen/Qwen2.5-1.5B-Instruct"  # 本地代理(中文原生小模型,CPU 可跑)
REVIEW_AT = 0.6
_HELDOUT_BENIGN = "samples/eval/heldout/benign-heldout.jsonl"
_WARMUP_ITEMS = 3
_ADMISSION_MIN_HELDOUT_SAMPLES = 30
_ADMISSION_MAX_HELDOUT_FPR = 0.10
_ADMISSION_MAX_P95_MS = 5_000.0
_CTX = Context(session_id="bench")
_DET = KeywordRuleDetector()


def _percentile_ms(latencies_s: list[float], percentile: float) -> float | None:
    """线性插值百分位数；输入为空时没有可解释的延迟指标。"""
    if not latencies_s:
        return None
    if not 0 <= percentile <= 100:
        raise ValueError("percentile 必须在 0 到 100 之间")
    values = sorted(latencies_s)
    rank = (len(values) - 1) * percentile / 100
    lower = math.floor(rank)
    upper = math.ceil(rank)
    value = values[lower] if lower == upper else values[lower] + (values[upper] - values[lower]) * (rank - lower)
    return round(value * 1000, 2)


def _admission(*, heldout_fpr: float | None, heldout_samples: int,
               latency_p95_ms: float | None, failures: int,
               degraded_calls: int) -> tuple[bool, list[str]]:
    """根据可复核的基准事实给出准入结论；不读取环境也不访问端点。"""
    reasons: list[str] = []
    if heldout_fpr is None:
        reasons.append("没有可计入的 held-out 良性输入")
    elif heldout_samples < _ADMISSION_MIN_HELDOUT_SAMPLES:
        reasons.append(f"held-out 良性输入仅 {heldout_samples} 条，少于 {_ADMISSION_MIN_HELDOUT_SAMPLES} 条")
    elif heldout_fpr > _ADMISSION_MAX_HELDOUT_FPR:
        reasons.append(f"held-out FPR {heldout_fpr:.1%} 超过 {_ADMISSION_MAX_HELDOUT_FPR:.1%}")
    if latency_p95_ms is None:
        reasons.append("没有可计入的端到端延迟")
    elif latency_p95_ms > _ADMISSION_MAX_P95_MS:
        reasons.append(f"P95 延迟 {latency_p95_ms:.0f}ms 超过 {_ADMISSION_MAX_P95_MS:.0f}ms")
    if failures:
        reasons.append(f"发生 {failures} 次 judge 后端失败/异常")
    if degraded_calls:
        reasons.append(f"有 {degraded_calls} 次调用处于 fail-safe 降级")
    return not reasons, reasons


def _reset_measurement_counters(counters: dict[str, int]) -> None:
    """预热只用于加载模型和连接，不计入正式测量或准入结论。"""
    counters.update(calls=0, failures=0, degraded_calls=0)


def _wrap(det: LlmJudgeDetector, label: str):
    """把检测器包装为带端到端耗时和 fail-safe 状态的 judge 探针。"""
    counters = {"calls": 0, "failures": 0, "degraded_calls": 0}

    def judge(text: str) -> tuple[bool, float]:
        started = time.perf_counter()
        was_degraded = det._degraded
        sp = SourceSpan(
            source_type=SourceType.USER, trust_level=TrustLevel.UNTRUSTED, content_hash="x",
            excerpt=text,
        )
        try:
            detected = bool(det.detect([sp], _CTX))
        except Exception:  # pragma: no cover - 当前检测器自身已 fail-safe，此处防止基准中断。
            detected = False
            counters["failures"] += 1
        elapsed = time.perf_counter() - started
        counters["calls"] += 1
        is_degraded = det._degraded
        if not was_degraded and is_degraded:
            counters["failures"] += 1
        if is_degraded:
            counters["degraded_calls"] += 1
        return detected, elapsed

    return judge, label, counters


def _make_judge():
    """judge 后端三选一,都包成真 LlmJudgeDetector(口径一致)。返回 (judge, 标签)。

    选择优先级:
      0) `LLM_BASE`(/v1 基址)统一后端 —— 供 run_suite 跨模型编排,与 redteam 同口径。
      1) `JUDGE_ENDPOINT` 显式本地自托管端点(合规闭环:judge 全离线、数据不出域)——
         配 `JUDGE_MODEL`、`JUDGE_NO_THINK=1`(Qwen3/MiMo 等推理模型关思考直出裁决)。
      2) `.env` 真云端点(OpenAI 兼容,如 DeepSeek/MiMo)。
      3) 本地 Qwen2.5-1.5B(transformers,CPU 离线回退)。
    """
    s = Settings()
    unified = os.environ.get("LLM_BASE", "").strip()
    local_ep = os.environ.get("JUDGE_ENDPOINT", "").strip() or unified
    if local_ep:
        # 私有化合规路径:judge 走客户本地自托管模型(同一台 llama-server/vLLM 即可),不调云。
        # JUDGE_* 优先,缺省回落到统一的 LLM_*(供 run_suite 编排)。
        model = os.environ.get("JUDGE_MODEL") or os.environ.get("LLM_MODEL", "local")
        api_key = os.environ.get("JUDGE_API_KEY") or os.environ.get("LLM_API_KEY", "")
        no_think = (
            os.environ.get("JUDGE_NO_THINK", os.environ.get("LLM_NO_THINK", "0")) == "1"
        )
        extra = {"chat_template_kwargs": {"enable_thinking": False}} if no_think else {}
        det = LlmJudgeDetector(endpoint=local_ep, api_key=api_key, model=model, extra_body=extra)
        label = f"{model} @ 本地自托管(air-gapped)"
        return _wrap(det, label)
    real = bool(s.model_api_key) and not any(
        h in s.model_endpoint for h in ("127.0.0.1", "localhost")
    )
    if real:
        det = LlmJudgeDetector(endpoint=s.model_endpoint, api_key=s.model_api_key, model=s.model_name)
        label = f"{s.model_name} @ 真端点"
    else:
        from transformers import AutoModelForCausalLM, AutoTokenizer

        tok = AutoTokenizer.from_pretrained(QWEN)
        model = AutoModelForCausalLM.from_pretrained(QWEN, torch_dtype="auto")
        base: list[dict[str, str]] = [{"role": "system", "content": _SYSTEM}]
        for q, a in _SHOTS:
            base += [{"role": "user", "content": q}, {"role": "assistant", "content": a}]

        def qwen_backend(text: str) -> bool:
            msgs = base + [{"role": "user", "content": text[:2000]}]
            prompt = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
            ids = tok(prompt, return_tensors="pt")
            out = model.generate(**ids, max_new_tokens=4, do_sample=False)
            gen = tok.decode(out[0][ids.input_ids.shape[1] :], skip_special_tokens=True)
            return "ATTACK" in gen.upper()

        det = LlmJudgeDetector(backend=qwen_backend)
        label = f"{QWEN}(本地代理)"

    return _wrap(det, label)


def _rule_held(text: str) -> bool:
    span = SourceSpan(
        source_type=SourceType.USER, trust_level=TrustLevel.UNTRUSTED, content_hash="x", excerpt=text
    )
    return max((f.score for f in _DET.detect([span], _CTX)), default=0.0) >= REVIEW_AT


def main() -> int:
    samples = [
        s
        for s in load_dataset("samples/eval/corpus")
        if s.input is not None and s.target_tool is None and s.reply is None
    ]
    heldout = [s for s in load_dataset(_HELDOUT_BENIGN) if s.input is not None]
    judge, label, counters = _make_judge()
    warmup_items = min(_WARMUP_ITEMS, len(samples))
    for sample in samples[:warmup_items]:
        judge(sample.input or "")
    _reset_measurement_counters(counters)
    rows = []
    latencies_s: list[float] = []
    for sample in samples:
        judged, elapsed = judge(sample.input or "")
        latencies_s.append(elapsed)
        rows.append({"mal": sample.ground_truth_malicious, "j": judged,
                     "r": _rule_held(sample.input or "")})
    heldout_rows = []
    for sample in heldout:
        judged, elapsed = judge(sample.input or "")
        latencies_s.append(elapsed)
        heldout_rows.append(judged)
    mal = [r for r in rows if r["mal"]]
    ben = [r for r in rows if not r["mal"]]
    nm, nb = len(mal), len(ben)
    heldout_fpr = sum(heldout_rows) / len(heldout_rows) if heldout_rows else None
    latency_p50_ms = _percentile_ms(latencies_s, 50)
    latency_p95_ms = _percentile_ms(latencies_s, 95)
    latency_p99_ms = _percentile_ms(latencies_s, 99)
    eligible, reasons = _admission(
        heldout_fpr=heldout_fpr, heldout_samples=len(heldout_rows),
        latency_p95_ms=latency_p95_ms, failures=counters["failures"],
        degraded_calls=counters["degraded_calls"],
    )

    def rate(rows_, pred):
        return sum(pred(r) for r in rows_) / len(rows_) * 100 if rows_ else 0.0

    mean_s = sum(latencies_s) / len(latencies_s) if latencies_s else 0.0
    print(
        f"\n输入子集 恶意{nm}/良性{nb} · held-out 良性{len(heldout_rows)} · judge={label}\n"
        f"预热{warmup_items}条(不计指标) · E2E延迟 P50/P95/P99="
        f"{latency_p50_ms}/{latency_p95_ms}/{latency_p99_ms}ms · "
        f"失败{counters['failures']} · 降级调用{counters['degraded_calls']} · "
        f"准入={'通过' if eligible else '不通过'}"
    )
    print(f"{'系统':<26}{'召回':>9}{'FPR':>9}")
    print(f"{'规则基线':<24}{rate(mal, lambda r: r['r']):>8.1f}%{rate(ben, lambda r: r['r']):>8.1f}%")
    print(f"{'LLM-judge 单跑':<23}{rate(mal, lambda r: r['j']):>8.1f}%{rate(ben, lambda r: r['j']):>8.1f}%")
    print(
        f"{'规则+LLM-judge 融合':<22}"
        f"{rate(mal, lambda r: r['j'] or r['r']):>8.1f}%{rate(ben, lambda r: r['j'] or r['r']):>8.1f}%"
    )
    print("\n[参照 benchmarks/p6-fusion-tuning.md] protectai 单跑 79.8%/47.1% · 规则+protectai 91.0%/52.9%")
    # 机读结果(run_suite 编排器解析)。
    print("##RESULT## " + json.dumps({
        "suite": "judge", "model": label,
        "judge_recall": round(rate(mal, lambda r: r["j"]) / 100, 4),
        "judge_fpr": round(rate(ben, lambda r: r["j"]) / 100, 4),
        "fused_recall": round(rate(mal, lambda r: r["j"] or r["r"]) / 100, 4),
        "fused_fpr": round(rate(ben, lambda r: r["j"] or r["r"]) / 100, 4),
        "heldout_fpr": round(heldout_fpr, 4) if heldout_fpr is not None else None,
        "heldout_samples": len(heldout_rows),
        "warmup_items": warmup_items,
        "latency_samples": len(latencies_s),
        "latency_p50_ms": latency_p50_ms,
        "latency_p95_ms": latency_p95_ms,
        "latency_p99_ms": latency_p99_ms,
        "failure_count": counters["failures"],
        "degraded_call_count": counters["degraded_calls"],
        "eligible": eligible,
        "reasons": reasons,
        "sec_per_item": round(mean_s, 2),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
