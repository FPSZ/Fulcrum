"""LLM-judge 语义检测实测 —— 在冻结语料输入子集量 LLM-judge 的召回/FPR,对比规则与专用分类器。

验证 P6 语义层走 LLM-judge(中文原生)而非英文专用分类器:judge 对中文良性咨询近零误报,
融合后保 FPR 补召回。本机用 Qwen2.5-1.5B-Instruct(CPU,transformers)作 MiMo 的可复现代理
(口径与 llm_judge 检测器的系统提示 + few-shot 一致);生产用 fulcrum.yml 配 MiMo 端点。

依赖 transformers/torch(本仓默认无,见 doc 08 §10)。
用法:HF_ENDPOINT=https://hf-mirror.com python samples/eval/benchmarks/llm_judge_bench.py
"""

from __future__ import annotations

import sys
import time

sys.path.insert(0, "src")

from fulcrum.capabilities.detectors.keyword_rules import KeywordRuleDetector  # noqa: E402
from fulcrum.capabilities.detectors.llm_judge import _SHOTS, _SYSTEM  # noqa: E402
from fulcrum.core.domain import Context, SourceSpan, SourceType, TrustLevel  # noqa: E402
from fulcrum.eval.dataset import load_dataset  # noqa: E402

MODEL = "Qwen/Qwen2.5-1.5B-Instruct"  # MiMo 代理(中文原生小模型,CPU 可跑)
REVIEW_AT = 0.6
_CTX = Context(session_id="bench")
_DET = KeywordRuleDetector()


def _make_judge():
    """本地 Qwen 作 LLM-judge,(text)->是否攻击;系统提示/few-shot 复用 llm_judge 检测器口径。"""
    from transformers import AutoModelForCausalLM, AutoTokenizer

    tok = AutoTokenizer.from_pretrained(MODEL)
    model = AutoModelForCausalLM.from_pretrained(MODEL, torch_dtype="auto")
    base: list[dict[str, str]] = [{"role": "system", "content": _SYSTEM}]
    for q, a in _SHOTS:
        base += [{"role": "user", "content": q}, {"role": "assistant", "content": a}]

    def judge(text: str) -> bool:
        msgs = base + [{"role": "user", "content": text[:2000]}]
        prompt = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
        ids = tok(prompt, return_tensors="pt")
        out = model.generate(**ids, max_new_tokens=4, do_sample=False)
        gen = tok.decode(out[0][ids.input_ids.shape[1] :], skip_special_tokens=True)
        return "ATTACK" in gen.upper()

    return judge


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
    judge = _make_judge()
    t0 = time.perf_counter()
    rows = [
        {
            "mal": s.ground_truth_malicious,
            "j": judge(s.input or ""),
            "r": _rule_held(s.input or ""),
        }
        for s in samples
    ]
    dt = time.perf_counter() - t0
    mal = [r for r in rows if r["mal"]]
    ben = [r for r in rows if not r["mal"]]
    nm, nb = len(mal), len(ben)

    def rate(rows_, pred):
        return sum(pred(r) for r in rows_) / len(rows_) * 100

    print(f"\n输入子集 恶意{nm}/良性{nb} · 模型 {MODEL} · {dt:.0f}s({dt / len(rows):.1f}s/条)\n")
    print(f"{'系统':<26}{'召回':>9}{'FPR':>9}")
    print(f"{'规则基线':<24}{rate(mal, lambda r: r['r']):>8.1f}%{rate(ben, lambda r: r['r']):>8.1f}%")
    print(f"{'LLM-judge 单跑':<23}{rate(mal, lambda r: r['j']):>8.1f}%{rate(ben, lambda r: r['j']):>8.1f}%")
    print(
        f"{'规则+LLM-judge 融合':<22}"
        f"{rate(mal, lambda r: r['j'] or r['r']):>8.1f}%{rate(ben, lambda r: r['j'] or r['r']):>8.1f}%"
    )
    print("\n[参照 benchmarks/p6-fusion-tuning.md] protectai 单跑 79.8%/47.1% · 规则+protectai 91.0%/52.9%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
