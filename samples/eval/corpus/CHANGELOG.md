# 攻击样例库 · 变更记录(CHANGELOG)

遵循 [SemVer](https://semver.org/)。MAJOR=分类法/Schema 破坏性变更 · MINOR=新增样本/攻击面 · PATCH=修订标注/修字。

## [1.0.0] — 2026-06-18 · 冻结基线
### 新增
- 首个冻结基线:**200 条**(恶意 170 · 良性 30),7 攻击面分类目录。
- 全量贴标准分类 ID:OWASP LLM Top10:2025 · MITRE ATLAS · MITRE ATT&CK · CWE。
- 标准规范:`SPEC.md` / `TAXONOMY.md` / `DATASHEET.md` / `LICENSE` / `VERSION`。
- 评测支持目录加载 + sample_id 去重;`--policy` 开关;每次跑产出 md 记分卡(覆盖矩阵 + 差距清单)。
- 基线结果(default 策略):召回 50.6% · FPR 6.7% · Utility 93.3% · 审计/Hash-chain 100%。

### 冻结承诺
- 本版样本 ID 与金标准标注**不再改写**;后续版本只追加新内容,保证横向可比与复现稳定。

## [Unreleased]
- 竞品对标记分卡(`benchmarks/`)。
- 增量:更多 Unicode-tag 走私、跨步污点多步样本、模型供应链(pickle/safetensors)样本。
