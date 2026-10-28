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

## [1.1.0] — 2026-09-04 · 伪权威攻击面扩展(+9)
### 新增(PR #115,配 `false_authority` 检测器)
- **间接注入·伪权威(5 条,恶意)**:`inj-i17` 假法规引用覆盖 · `inj-i18` 伪造授权函 · `inj-i19` 假管辖权主张 · `inj-i20` 政策傀儡(诱导改写安全策略)· `inj-i21` 伪造官方公文。攻击面 `indirect.fake_authority*`:不可信内容**自封权威**(法规/官方/授权)诱导模型覆盖既有安全判断。真值依据:OWASP LLM01/LLM04、MITRE AML.T0051.001;安全应然标准均判 block/approve(见各条 `expected_action`)。
- **知识投毒·伪法规(1 条,恶意)**:`poi-17` 假法规写入长期记忆。LLM04;expected=block。
- **良性硬负例(3 条)**:`neg-17` 合法法规引用问答 · `neg-18` 合法新旧政策更替 · `neg-19` 用户本人授权的合法导出。防伪权威检测误伤日常政务引用。
### 口径
- 样本 200→**209**(恶意 170→176 · 良性 30→33,良性占比 15.8%)。**v1.0.0 冻结承诺不变**:原 200 条 ID/金标准未改写,本版仅追加。
- 与 v1.0.0 横向对比请分母对齐:整机召回不可直接相比(v1.0.0=200 条口径)。

## [Unreleased]
- **基线重测(2026-06-24)**:样本未变,评测装配对齐生产(keyword_rules + secret_egress + manifest_guard + disclosure_egress + sequence 链)后,default 召回 50.6%→**75.3%** · FPR 6.7%→**0.0%** · Utility **100%**(gov_demo 召回 **78.8%**)。初版低分系"评测用 M0 桩装配考"的测量假象。详见 `docs/eval/corpus-gap-report.md`。
- 竞品对标记分卡(`benchmarks/`)。
- 增量:更多 Unicode-tag 走私、跨步污点多步样本、模型供应链(pickle/safetensors)样本。
