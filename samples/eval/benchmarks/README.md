# 竞品对标(Benchmarks)

> 用冻结的攻击样例库给**同类系统**打分,拿横向对比——类比 AV-TEST/AV-Comparatives 用统一样本集横评杀软。

## 怎么用
`run_bench.py` 取库内**输入级**样本(竞品多为纯输入侧注入分类器,只这批可比),同一批文本喂给各检测器,
按金标准算 **检出率(召回)/ FPR / 分桶召回**。检测器即插即用:依赖/模型不可达则跳过并记录。

```bash
# 枢衡自身(本仓库 venv):
.venv/Scripts/python samples/eval/benchmarks/run_bench.py --only fulcrum

# 竞品(需 torch/transformers 环境;国内经 hf-mirror 拉模型):
HF_ENDPOINT=https://hf-mirror.com <py-with-torch> samples/eval/benchmarks/run_bench.py --only protectai,deepset
```

## 已接竞品(适配器在 run_bench.py)
- `protectai/deberta-v3-base-prompt-injection-v2` —— 主流注入分类器(实测)
- `deepset/deberta-v3-base-injection` —— 早期注入分类器(实测)
- `meta-llama/Llama-Prompt-Guard-2-86M` —— 受限模型,需 HF 许可(默认跳过)
- 待接:ProtectAI **LLM Guard**、**NeMo Guardrails**、**Rebuff**、**Vigil**、Lakera/Azure/Bedrock(API,取公开口径)

## 结论
见 [`scorecard.md`](scorecard.md):专用分类器检出率高(84–99%)但 FPR 灾难(47–94%,政务场景不可用);
枢衡当前规则精准(FPR 11.8%)但欠召回。→ 输入层引分类器补召回 + 保精准 + 守住工具/出口/供应链/审计四层差异化。

## 注意
- 对比限**输入子集**;工具管控/出口/供应链/审计是枢衡差异化覆盖,竞品不涉及。
- 良性样本 17 条,FPR 置信区间偏宽,但量级差异结论稳健。
- 竞品判定:文本分类器输出"注入/恶意"标签即记为"检出"。

## Agentic 间接注入 harness(2026-06,见 docs/plan/08 §12.5)

上面 `run_bench.py` 是**输入级文本分类**横评;这组是**带工具的多轮 agent** 间接注入(IPI)实测——
注入藏进**工具返回**,量"模型自身 ASR"与"接枢衡后 ASR"。需先起本地模型代理:

- `local_model_proxy.py <port>` —— 把 MiMo(创作者免费,密钥取自 `.env`/Settings)接成 `localhost/v1`
  OpenAI 兼容后端,自动注入 `enable_thinking:false`(MiMo 是推理模型,不关思考会空返回/超时)。**无硬编码密钥**。
- `gov_agentic_redteam.py` —— **政务领域硬集 v2**(中文场景+我们的工具+我们的检测)。**18 场景**分 leak/escalate
  两类:实测 MiMo 自身 ASR **72.2%**(leak 87% / escalate 0%),接枢衡 leak 100%→0%;附 judge/闸门双误报探针。
  跑:`local_model_proxy.py 8123` 后 `uv run python samples/eval/benchmarks/gov_agentic_redteam.py`。
- `gov_agentic_realistic.py` —— **真实厚 agent v3**(对标泄露的 Manus 系统提示结构/厚度/安全占比 + 官方
  SKILL.md 渐进披露 + 知识库 RAG 多轮铺垫)。`GOV_SAFETY=strict/loose`、`GOV_ATTACK=dilute/crescendo`、
  `GOV_PAD_LEVELS` 可切换。核心发现:**agent 自防是"提示写法的函数"(strict 0% ↔ loose 100% 二极管)、
  出口闸门恒定 0%**;crescendo 多轮未优于单发(诚实负结果)。详见 docs/plan/08 §12.6。
- **跨模型自防可靠性(§12.8)** —— 两脚本都直连 `LOCAL_LLM_PORT`(默认 8123)的 OpenAI 兼容端点,
  可换任意本地 model。实测真实政务档位 **Qwen3-14B**(本地 `llama-server` ROCm/HIP):
  `llama-server -m Qwen3-14B-Q4_K_M.gguf --port 8123 --jinja -ngl 99 -c 32768 --alias mimo` 后
  `LOCAL_LLM_PORT=8123 uv run python ...redteam.py`。结果:自身 ASR **94.4%**、leak **100%**、
  连明文 strict 也 **100% 无视**(MiMo 偏守端、14B 偏破端——**二极管翻转点是"模型的函数"**),
  出口闸门跨两模型恒定 **0%/拦 100%/0 误报**。
- `agentdojo_fulcrum.py` —— 把枢衡检测器作为 defense 插入公认基准 **AgentDojo(NeurIPS'24)**;
  MiMo banking + `important_instructions` 裸基线 ASR **58.3%**(与政务硬集互为印证)。需 agentdojo venv。
- `invariant_bench.py` —— **同形态竞品对标**:Invariant Guardrails(invariantlabs-ai,430⭐,规则化
  agent 网关)vs 枢衡出口闸门,在 18 场景 leak 外发地址上**检出/误报等价(16/16、0/3)**;差异化在
  政务特化+judge 语义+样例库。跑:`uv run --with invariant-ai python samples/eval/benchmarks/invariant_bench.py`。
- `llm_judge_bench.py` —— **LLM-judge 语义层召回/FPR**(冻结语料输入子集,89 恶意/17 良性)。新增
  **本地自托管(air-gapped)合规路径**:judge 走客户**本地模型**、数据不出域、零云调用——满足政务
  "输入不外发"红线。实测本地 `llama-server`:**Qwen3-8B 规则+judge 融合召回 88.8% / FPR 0% / 0.6s 条**、
  Qwen3-14B 86.5% 单跑 / 同 88.8% 融合(融合后 8B 即够,judge 复用客户已部署模型零额外成本);
  对照英文分类器 protectai 单跑 79.8% 但 **FPR 47%**(政务不可用)。跑(先起本地端点):
  `JUDGE_ENDPOINT=http://127.0.0.1:8123/v1 JUDGE_MODEL=qwen3-8b JUDGE_NO_THINK=1 uv run python samples/eval/benchmarks/llm_judge_bench.py`。
  生产启用见 `src/fulcrum/config/fulcrum.yml` 的 `options.llm_judge`(同一通道,即插即用)。
