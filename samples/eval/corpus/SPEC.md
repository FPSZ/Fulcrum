# 枢衡攻击样例库 · 数据规范(SPEC)

> 本规范定义样例库的**字段 Schema、ID 命名、严重度评级、真值标注协议**。冻结于 v1.0.0,变更走 SemVer。
> 机读实现:`src/fulcrum/eval/dataset.py::EvalSample`。

## 1. 文件格式
- **JSONL**:每行一条 JSON 对象(UTF-8)。`#` 开头行与空行为注释/留白,加载时跳过。
- **目录加载**:`samples/eval/corpus/` 下递归收集全部 `*.jsonl`(下划线开头文件跳过),合并为一个数据集;`sample_id` 全局唯一(撞号报错)。

## 2. 字段 Schema

| 字段 | 必填 | 类型 | 说明 |
|---|---|---|---|
| `sample_id` | ✅ | str | 稳定唯一 ID,见 §3 命名规范 |
| `attack_type` | ✅ | str | 攻击大类(见 §4) |
| `ground_truth_malicious` | ✅ | bool | 金标准:是否恶意 |
| `expected_action` | ✅ | enum | 期望处置:`allow`/`sanitize`/`approve`/`block` |
| `input` / `reply` / `target_tool`+`tool_args` | ✅(三选一) | — | 载荷;决定路由(见 §5) |
| `scenario` | | str | 场景,默认 `govoffice` |
| `source_type` | | str | 来源角色:`user`/`assistant`/… |
| `expected_trace_source` | | str | 归因金标准来源(document/webpage/retrieval/memory/tool_return/plugin_manifest) |
| `notes` | | str | 标注说明(常含"为何难/当前是否漏") |
| `technique` | | str | 细分手法 slug,如 `ssrf.cloud_metadata.aliyun` |
| `owasp` | | str | OWASP LLM Top10:2025,如 `LLM01:2025` |
| `mitre_atlas` | | str | MITRE ATLAS,如 `AML.T0051.001` |
| `mitre_attack` | | str | MITRE ATT&CK,如 `T1059.001` |
| `cwe` | | str | CWE,如 `CWE-1427` |
| `severity` | | enum | `critical`/`high`/`medium`/`low`(见 §6) |
| `source` | | str | `self`(自建)/ `upstream:<repo>`(情报源) |
| `version_added` | | str | 入库版本(SemVer),如 `1.0.0` |
| `references` | | list[str] | 参考链接(可选) |
| `tags` | | list[str] | 自定义标签 |

> Pydantic 默认忽略多余键,故未来加字段向后兼容。

## 3. ID 命名规范
`<前缀>-<序号>`,前缀按攻击面固定:
`tg-file` 敏感文件 · `tg-path` 路径穿越 · `tg-ssrf` SSRF · `tg-cmd` 命令 · `tg-exfil` 外泄/高危动作 ·
`inj-d` 直接注入 · `inj-i` 间接注入 · `enc` 编码/Unicode · `jb` 越狱 · `poi` 投毒 · `sc` 供应链 · `eg` 出口 · `neg` 硬负例。
冻结后 ID 不复用、不改写;新内容只追加。

## 4. attack_type 取值
`direct_prompt_injection` · `indirect_injection` · `jailbreak` · `knowledge_poisoning` ·
`unauthorized_tool` · `data_exfiltration` · `data_leak` · `data_poisoning` · `supply_chain` · `benign`。

## 5. 路由(由载荷决定,优先级从高到低)
1. 有 `target_tool` → **工具级**,过 `evaluate_intent`(策略判定)。
2. 否则有 `reply` → **出口级**,过 `screen_output`(出口闸门)。
3. 否则 → **输入级**,过 `screen_input`(输入闸门)。

## 6. 严重度评级(severity)
| 级别 | 判据 |
|---|---|
| `critical` | 直接导致凭据/名册外泄、RCE、域级凭据、不可逆破坏 |
| `high` | 单机凭据/越权读写、危险命令、SSRF 内网、系统提示泄露 |
| `medium` | 偏见投毒、单条 PII、侦察类泄露、需多步才成害 |
| `low` | 弱信号、需强配合、硬负例 |

## 7. 真值标注协议
- `ground_truth_malicious` 与 `expected_action` 按**安全应然标准**标注——即一个**正确实现**的网关**应当**如何处置,**不**取决于当前实现能否检出。
- 因此跑库得到的漏判率 = 当前实现与应然标准的差距(差距报告/加固待办的来源),而非标注错误。
- `expected_action` 分档语义:`block` 硬拦不可放行 · `approve` 挂起转人工 · `sanitize` 脱敏后放行 · `allow` 放行。
