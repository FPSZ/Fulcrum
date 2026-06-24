# 枢衡攻击样例库(Fulcrum Attack Corpus)

> 政企智能体安全网关的**高难度对抗评测基准**。对标杀软病毒库:标准化、可冻结、可复现、每次跑出标准报告。
> 这是产品的**核心可售资产**——年订阅 + 持续更新(见 [`docs/plan/08`](../../../docs/plan/08-攻击样例库与对标基准.md))。

## 它是什么
- **样本库(zoo)**:200 条分类化攻击/良性样本,每条挂 OWASP/MITRE-ATLAS/ATT&CK/CWE 标准 ID。
- 专测"模型自身不会拒、必须靠网关"的硬样本:语义注入、混淆/Unicode 走私、跨步污点、SSRF、LOLBins、知识/记忆投毒、供应链。
- 与"特征库(检测规则,在 `src/` 代码里)"分离:本库是考卷,拿它考网关 → 差距报告。

## 目录(按攻击面)
| 目录 | 攻击面 | 赛题目标 |
|---|---|---|
| `01-input-injection/` | 直接/间接注入、编码/Unicode 走私 | ① 攻击识别 |
| `02-jailbreak/` | 越狱(多轮/语义/混淆) | ① |
| `03-toolguard/` | 敏感文件/路径穿越/SSRF/命令/外泄 | ② 工具管控 |
| `04-poisoning/` | 知识/记忆投毒 | ①④ |
| `05-supplychain/` | 插件/Skill/MCP 清单 | ③ 供应链 |
| `06-egress/` | 出口防泄露(PII/名册/系统提示/渲染外泄) | ④ 审计 |
| `benign/` | 硬负例(形似攻击实则合法,量 FPR) | — |

规范:`SPEC.md`(Schema/ID/严重度/标注协议)· `TAXONOMY.md`(分类 ID 映射)· `DATASHEET.md`(数据集说明书)· `CHANGELOG.md`/`VERSION`(版本)· `LICENSE`。

## 怎么跑(每次产出标准报告)
```bash
# 整库回放,产出 md 记分卡 + json 明细(默认策略 gov_demo)
python -m fulcrum.eval --dataset samples/eval/corpus --out docs/eval/results/latest.json

# 切策略对比(default 含 http.request 网络规则)
python -m fulcrum.eval --dataset samples/eval/corpus --policy data/policies/default.yml \
  --out docs/eval/results/corpus-default.json
```
报告含:主指标(召回/FPR/精确率/ASR/Utility/处置准确率/审计完整率)+ 按 OWASP/严重度覆盖矩阵 + 分桶表 + FN/FP 差距清单。

## 版本与订阅
- **SemVer + 冻结基线**:当前 `v1.0.0`(见 `VERSION`)。基线样本 ID/标注冻结,新内容只追加。
- **订阅交付**:季度增量(新手法 + 新 CVE/技术映射)+ 每次增量的"检出 delta"。
- **外部情报源**:`../upstream/feeds.yml` 登记维护中的开源攻击语料(garak/PayloadsAllTheThings/LOLBAS/HarmBench/agentdojo 等),引用不内置(license 干净)。

## 当前基线(v1.0.0,评测装配对齐生产)
200 条 · default 策略:召回 75.3% · FPR 0.0% · Utility 100% · 审计 100%(gov_demo 策略召回 78.8%)。
按闸门分域:工具层 90%(gov_demo 100%)、出口层 90% 已强,输入层 62% 为短板(语义攻击撞规则天花板,待 `llm_judge` 默认启用)= 加固路线图,详见 [`docs/eval/corpus-gap-report.md`](../../../docs/eval/corpus-gap-report.md)。
