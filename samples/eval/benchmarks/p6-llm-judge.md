# P6 语义层 · LLM-judge 实测(中文原生)

> 接续 `p6-fusion-tuning.md` 的结论(英文专用分类器对中文政务 FPR 47% 无救),验证语义层改走 **LLM-as-judge**。
> 复现:`python samples/eval/benchmarks/llm_judge_bench.py`(`.env` 配 OpenAI 兼容真模型即走真端点,否则回退本地 Qwen)。
> 数据集:`samples/eval/corpus` v1.0.0 · 输入级子集(恶意 89 · 良性 17)。两种后端均经**真 `LlmJudgeDetector`**测(口径完全一致)。

## 结论

**LLM-judge(中文原生)是 P6 语义层的正确解:近零误报地补召回,且模型越强召回越高。**

| 系统 | 召回 | FPR |
|---|---|---|
| 规则基线(keyword_rules) | 59.6% | 11.8% |
| **LLM-judge 单跑(deepseek-chat,真端点)** | **94.4%** | **0.0%** |
| **规则 + LLM-judge 融合(deepseek-chat)** | **95.5%** | **11.8%**(不变) |
| LLM-judge 单跑(Qwen2.5-1.5B,本地代理) | 56.2% | 0.0% |
| 规则 + LLM-judge 融合(Qwen-1.5B) | 77.5% | 11.8% |
| (参照)protectai 专用分类器单跑 | 79.8% | **47.1%** |
| (参照)规则 + protectai | 91.0% | **52.9%** |

## 为什么 judge 赢

1. **零误报**:judge 正确放行"科普 /etc/passwd 各列含义""问 API key 是什么"等中文良性咨询——这正是英文专用分类器(对中文过度自信判注入)栽跟头之处。**FPR 0.0% vs 47.1%**,两种模型都做到。
2. **保 FPR 补召回**:融合(规则 OR judge)召回大涨而 **FPR 零增长**(judge 不引入任何良性误报);protectai 融合则把 FPR 推到 52.9% 灾难。
3. **模型越强召回越高**:换 1.5B 小模型 → deepseek-chat,judge 单跑召回 **56.2% → 94.4%**、融合 **77.5% → 95.5%**,FPR 始终 0%/11.8%。说明这套语义层的天花板由所配 LLM 决定,生产配强中文模型(MiMo/DeepSeek)即得高召回。
4. **互补**:judge 偶尔漏的编码混淆样本(base64/hex,judge 看见乱码判 SAFE),正由规则的解码复扫(P1)兜住;规则漏的语义改写由 judge 兜。两层正交。

> judge 单独贡献封顶 `max_score=0.7`(独自最多挂人工复核,不自动拦截),与规则命中综合才达拦截——FPR 守在规则基线水平。

## 落地

- 新增能力 `detector/llm_judge`(`detectors/llm_judge.py`):OpenAI 兼容端点(默认 MiMo)、缺端点/异常**自动降级 no-op**(fail-safe,绝不拖垮规则基线、绝不因故障反而拦一切)、**默认不入装配**。
- 启用:fulcrum.yml `detectors` 加 `llm_judge`,`options.llm_judge` 配 `endpoint`/`model`/`api_key`。
- 端点/密钥/模型经构造参数注入(组装根从 Settings 取),能力层不 import 配置(守 capabilities→core 边界)。

---
*由 `samples/eval/benchmarks/llm_judge_bench.py` 实测产出。关联:[09 检测规则强化] §5/§6 · `p6-fusion-tuning.md`(分类器路线对比)。*
