"""LLM-judge 语义检测实测 —— 在冻结语料输入子集量 LLM-judge 的召回/FPR,对比规则与专用分类器。

验证 P6 语义层走 LLM-judge(中文原生)而非英文专用分类器:judge 对中文良性咨询近零误报,
融合后保 FPR 补召回。两种后端均经**真 LlmJudgeDetector**测(口径完全一致):
  · 真端点(优先):.env 配 OpenAI 兼容真模型(如 DeepSeek `deepseek-chat`、MiMo)→ 走检测器默认 HTTP 后端。
  · 本地代理(回退):Qwen2.5-1.5B-Instruct(CPU,transformers)注入为后端,无端点也可离线复现。

依赖:真端点模式需 .env(httpx 已是基础依赖);本地代理模式需 transformers/torch(见 doc 08 §10)。
用法:python samples/eval/benchmarks/llm_judge_bench.py
"""

from __future__ import annotations

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
_CTX = Context(session_id="bench")
_DET = KeywordRuleDetector()


def _wrap(det: LlmJudgeDetector, label: str):
    """把 LlmJudgeDetector 包成 (text)->bool 的 judge,并附标签。"""

    def judge(text: str) -> bool:
        sp = SourceSpan(
            source_type=SourceType.USER, trust_level=TrustLevel.UNTRUSTED, content_hash="x",
            excerpt=text,
        )
        return bool(det.detect([sp], _CTX))

    return judge, label


def _make_judge():
    """judge 后端三选一,都包成真 LlmJudgeDetector(口径一致)。返回 (judge, 标签)。

    选择优先级:
      1) `JUDGE_ENDPOINT` 显式本地自托管端点(合规闭环:judge 全离线、数据不出域)——
         配 `JUDGE_MODEL`、`JUDGE_NO_THINK=1`(Qwen3/MiMo 等推理模型关思考直出裁决)。
      2) `.env` 真云端点(OpenAI 兼容,如 DeepSeek/MiMo)。
      3) 本地 Qwen2.5-1.5B(transformers,CPU 离线回退)。
    """
    s = Settings()
    local_ep = os.environ.get("JUDGE_ENDPOINT", "").strip()
    if local_ep:
        # 私有化合规路径:judge 走客户本地自托管模型(同一台 llama-server/vLLM 即可),不调云。
        extra = (
            {"chat_template_kwargs": {"enable_thinking": False}}
            if os.environ.get("JUDGE_NO_THINK") == "1"
            else {}
        )
        det = LlmJudgeDetector(
            endpoint=local_ep,
            api_key=os.environ.get("JUDGE_API_KEY", ""),
            model=os.environ.get("JUDGE_MODEL", "local"),
            extra_body=extra,
        )
        label = f"{os.environ.get('JUDGE_MODEL', 'local')} @ 本地自托管(air-gapped)"
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
    judge, label = _make_judge()
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

    print(f"\n输入子集 恶意{nm}/良性{nb} · judge={label} · {dt:.0f}s({dt / len(rows):.1f}s/条)\n")
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
