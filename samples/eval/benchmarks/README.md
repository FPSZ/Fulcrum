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
