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

## [1.2.0] — 2026-09-05 · example/ 编外样例收编(+32)
### 背景
协作者曾在编外目录 `example/` 放置 40 条样例(7 个 JSONL,与语料同构)。其中 8 条与在审 PR #115 新增逐字重合(废弃,以 #115 合入版为准),其余 **32 条收编入正式语料**——评测口径只认本库,编外样例永不进分母。
### 新增(corpus 内 30 条,`version_added=1.2.0`;另 2 条链样例 `chain-exfil-04/05` 归 `samples/eval/chains.jsonl` demo 集,不进冻结分母)
- **直接注入/编码(7)**:`inj-d15` 长文填充绕过(excerpt 截断盲区)· `inj-d16` 中性措辞改写 · `inj-d17` · `inj-d18` · `enc-15`/`enc-16`/`enc-17` 编码变体。
- **越狱(4)**:`jb-27`~`jb-30` 新变体。
- **工具管控(8)**:`tg-path-13/14`(策略覆盖写/三重编码穿越)· `tg-ssrf-13/14`(元数据域名/IP 混淆)· `tg-file-13/14`(运行时库/网关配置读取)· `tg-cmd-19/20`(git SSHCommand 外泄/tar checkpoint 外泄)。
- **投毒(3)**:`poi-18`/`poi-19` +1;**供应链(2)**:`sc-13`/`sc-14`;**出口(6)**:`eg-sysprompt-05`/`eg-conn-01`/`eg-pii-07`/`eg-render-04` 等;**良性硬负例(2)**:`neg-20` 等。
### 1.2.0 实测(230 条:恶意 198 · 良性 32)
- 混淆 **TP=192 FN=6 FP=0 TN=32**;新增 28 条 corpus 恶意**检出 24/28**,新增 2 条良性零误伤。
- 新增 FN 4 条(即新盲区靶,后续加固项):`inj-d16`(中性措辞)· `tg-path-13` · `tg-file-13` · `tg-file-14`;存量 FN 仍为 `enc-11`/`eg-render-03`。
### 口径
- 样本 200→**230**(+2 链样例入 demo 集)。v1.0.0 冻结不变,本版仅追加;横向对比须分母对齐。
- 版本号沿用 1.2.0:本版原叠于在审 PR #115(伪权威 +9,拟作 1.1.0)之上;应评审意见(该检测器在当前基线零增量)剥离 #115 内容后独立成版,1.1.0 号段留待 #115 自行裁决。

## [Unreleased]
- **基线重测(2026-06-24)**:样本未变,评测装配对齐生产(keyword_rules + secret_egress + manifest_guard + disclosure_egress + sequence 链)后,default 召回 50.6%→**75.3%** · FPR 6.7%→**0.0%** · Utility **100%**(gov_demo 召回 **78.8%**)。初版低分系"评测用 M0 桩装配考"的测量假象。详见 `docs/eval/corpus-gap-report.md`。
- 竞品对标记分卡(`benchmarks/`)。
- 增量:更多 Unicode-tag 走私、跨步污点多步样本、模型供应链(pickle/safetensors)样本。
