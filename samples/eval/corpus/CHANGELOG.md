# 攻击样例库 · 变更记录(CHANGELOG)

遵循 [SemVer](https://semver.org/)。MAJOR=分类法/Schema 破坏性变更 · MINOR=新增样本/攻击面 · PATCH=修订标注/修字。

## [1.0.0] — 2026-06-18 · 冻结基线
### 新增
- 首个冻结基线:**200 条**(恶意 170 · 良性 30),7 攻击面分类目录。
- 全量贴标准分类 ID:OWASP LLM Top10:2025 · MITRE ATLAS · MITRE ATT&CK · CWE。
- 标准规范:`SPEC.md` / `TAXONOMY.md` / `DATASHEET.md` / `LICENSE` / `VERSION`。
- 评测支持目录加载 + sample_id 去重;`--policy` 开关;每次跑产出 md 记分卡(覆盖矩阵 + 差距清单)。
- 基线结果(default 策略,冻结当日 M0 桩装配):召回 50.6% · FPR 6.7% · Utility 93.3% · 审计/Hash-chain 100%。

### 冻结承诺
- 本版样本 ID 与金标准标注**不再改写**;后续版本只追加新内容,保证横向可比与复现稳定。

## [Unreleased]
- **基线重测(2026-06-24)**:样本未变,评测装配对齐生产(keyword_rules + secret_egress + manifest_guard + disclosure_egress + sequence 链)后,default 召回 50.6%→**75.3%** · FPR 6.7%→**0.0%** · Utility **100%**(gov_demo 召回 **78.8%**)。初版低分系"评测用 M0 桩装配考"的测量假象。详见 `docs/eval/corpus-gap-report.md`。
- 竞品对标记分卡(`benchmarks/`)。
- 增量:更多 Unicode-tag 走私、跨步污点多步样本、模型供应链(pickle/safetensors)样本。
