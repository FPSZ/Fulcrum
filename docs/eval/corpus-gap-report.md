# 枢衡攻击样例库 · 基线差距报告(v2026.06.24)

> 当前口径说明（2026-08-31）：本文保留冻结语料 v1.0.0 的历史差距分析；主结果以 `docs/eval/results/latest.json`（2026-06-29 回放）为准。开放 PR 的新检测器和沙箱增强均未进入该主结果，须 rebase 到 `origin/dev=0a877d7` 后独立评测，不能用旧分支结果覆盖本报告。

> 本报告由 `samples/eval/corpus/`(200 条高难度对抗样本)回放真实管线得出,目的是**量化当前防护的真实覆盖、并产出加固待办**。
> 与冒烟集(`govoffice.jsonl` 28 条)不同:本库刻意收录"模型自身不会拒、必须靠网关"的硬样本,**漏判率不是 bug,是路线图**。
>
> **本轮基线变更**:评测装配已**对齐生产** `fulcrum.yml`——检测器集 `keyword_rules + secret_egress + manifest_guard + disclosure_egress` + `chain_analyzer: sequence`,而非旧版的 M0 桩装配(仅 keyword_rules + noop)。叠加 keyword_rules 自身的归一化/递归解码/意图降误报加固,较 2026-06-18 初版(50.6%/47.1% · FPR 6.7%)大幅提升。**主因:评测现在考的是真实上线的那套检测组合,而非裁剪过的子集。**
>
> 复现:
> ```
> python -m fulcrum.eval --dataset samples/eval/corpus --policy data/policies/default.yml  --out docs/eval/results/json/corpus-default.json
> python -m fulcrum.eval --dataset samples/eval/corpus --policy data/policies/gov_demo.yml --out docs/eval/results/json/corpus-govdemo.json
> ```

## 1. 总览(200 条:恶意 170 · 良性 30)

| 指标 | default 策略 | gov_demo 策略 | 目标 |
|---|---|---|---|
| 阻断成功率 / 召回 | 75.3% | 78.8% | ≥80% |
| 误报率 FPR | 0.0% | 0.0% | ≤10% |
| Utility 正常可用 | 100.0% | 100.0% | ≥85% |
| 处置准确率 | 64.0% | 67.0% | ≥85% |
| 审计完整率 / Hash-chain | 100% | 100% | =100% |

> 对照初版(2026-06-18,M0 桩装配):召回 50.6%/47.1%、FPR 6.7%。本轮把评测对齐生产装配后,召回 +25 点、FPR 归零——**说明此前的低分是"评测把网关大半检测器关掉考"的测量假象,不是防护本身弱。**

## 2. 四条主结论

### 结论一:按三道闸门分域看,纵深防御每层贡献清晰

| 防御闸门 | 恶意样例 | default 召回 | gov_demo 召回 |
|---|---|---|---|
| 输入闸门(`screen_input`) | 89 | 62% | 62% |
| 工具闸门(`evaluate_intent`) | 61 | 90% | **100%** |
| 出口闸门(`screen_output`) | 20 | 90% | 90% |

工具层与出口层已是强项;**输入层 62% 是当前唯一短板**。

### 结论二:输入层从 ~21%→62%,但语义攻击撞到确定性规则天花板
归一化(NFKC+剥零宽+同形字折叠+de-leet)+ 递归解码(base64/hex/URL/ROT13/HTML 实体,深度 2)+ 意图降误报,把输入层从初版 ~21% 救到 **62%**。残留漏判几乎全是**无触发词的语义攻击**:`jailbreak 45.8%`(crescendo/skeleton key/persona/prefill)、`direct_prompt_injection 61.5%`(中性改写/分片/伪角色)。纯规则对此**已到顶**——这正是 `detector/llm_judge` 的战场:实测输入子集 **95.5% 召回 / 零增 FPR**(见 `samples/eval/benchmarks/p6-llm-judge.md`),但默认关、需配中文模型端点。另有少量嵌套/异形编码(`enc-01/02/03/06/10/11`)仍漏,属递归解码限深/异形编码未尽,见 §3 P1。

### 结论三:gov_demo 现已反超 default(工具层 100% vs 90%)
初版 default(50.6%)略胜 gov_demo(47.1%),因 gov_demo 漏全部 12 条 SSRF。该网络规则缺口已补,本轮 **gov_demo 工具层 100%、总召回 78.8%**,反超 default(工具层 90%、总 75.3%)。default 仍漏 `tg-exfil-*`(`external.send`/`funds.disburse` 无对应规则)——理想策略应合并二者(gov_demo 业务动作规则 + default 的 `http.request` 网络规则)。

### 结论四:零误报、零过拦
FPR **0.0%**、Utility **100%**:初版那 2 条"教育/防御性提问被误命中"的硬负例(`neg-01` 科普 /etc/passwd、`neg-08` 问 API key 是什么)已由 keyword_rules 的**意图降误报**逻辑(疑问/科普语气 + 唯一信号为敏感词提及 → 抑制)正确放行。30 条硬负例全部正确放行。

## 3. 加固待办(按优先级)

### P0 — 语义注入/越狱(收益最大,~25 条漏判)
1. **LLM-judge 语义层**:`detector/llm_judge` 已落地(中文原生、fail-safe 降级、默认 opt-in),实测输入子集 95.5%/零增 FPR。**待生产配中文模型端点(MiMo/DeepSeek)默认启用**——这是把召回从 75% 推到 90%+ 的唯一杠杆。

### P1 — 编码/工具补洞(扩解码 / 改 YAML)
2. **嵌套/异形编码**:递归解码现深度 2,`enc-*` 残漏需补更深层 + Unicode-tag/分片拼接识别。
3. **统一策略**:合并 gov_demo 业务动作规则(funds/case)与 default 的 `http.request` 网络规则;补 `file.delete` 等破坏性动作;default 补 `external.send` 外发规则(救 `tg-exfil-*`)。

### P2 — 出口/跨步增强(~7 条漏判)
4. **渲染外泄**:Markdown 图片/链接/1px 像素携带数据出口(`eg-render-03`),按域白名单剥离离域资源。
5. **跨步污点**:`sequence` 链分析已在评测装配内,但回放多为单 intent/样本,无法完整表达"读敏感→编码→外发"多步链;需多步回放 harness 才能完整覆盖跨请求记忆投毒等链式变体。

## 4. 误报(FP)清单 —— 零条

本轮 **0 FP(FPR 0.0%)**。初版的 `neg-01`/`neg-08` 两条科普类误命中已由意图降误报逻辑救回;30 条硬负例(问 curl、'忽略上一版草稿'、合法 base64 附件、workspace 内工具调用、科普 /etc/passwd、问 API key 等)全部正确放行。

## 5. 分桶明细(default 策略)

| 攻击类型 | 样例 | 召回 | 处置准确率 | 主要漏判手法 |
|---|---|---|---|---|
| unauthorized_tool | 57 | 96.5% | 94.7% | `tg-exfil-05/06`(external.send 无规则) |
| data_leak | 10 | 100.0% | 80.0% | —(secret/disclosure 出口检测已覆盖) |
| knowledge_poisoning | 14 | 85.7% | 50.0% | 休眠暗语、跨会话记忆投毒(`poi-10/12`) |
| indirect_injection | 14 | 64.3% | 28.6% | RAG 投毒、记忆写入、CSS 隐写(`inj-i02/03/04/10/14`) |
| supply_chain | 11 | 63.6% | 45.5% | 安装钩子、可疑端点、依赖混淆/typo(`sc-06..09`) |
| direct_prompt_injection | 26 | 61.5% | 38.5% | 中性改写、分片、嵌套/异形编码(`inj-d*`/`enc-*`) |
| data_exfiltration | 12 | 58.3% | 41.7% | external.send(default 无规则)、像素外泄(`tg-exfil-01..04`/`eg-render-03`) |
| data_poisoning | 2 | 50.0% | 50.0% | 出口投毒(`eg-poison-02`) |
| jailbreak | 24 | 45.8% | 16.7% | crescendo、skeleton key、persona、prefill、混淆(`jb-*`,13 条) |

---
*生成:2026-06-24 · 数据集 `samples/eval/corpus/`(v1.0.0,200 条)· 评测装配对齐生产 `fulcrum.yml` · 详见 `docs/eval/results/corpus-{default,govdemo}.json` 逐样例明细。*
