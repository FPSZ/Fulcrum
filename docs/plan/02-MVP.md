# 枢衡 Fulcrum MVP 实施计划

> 定位:本文是 **M1 功能清单**,**前置依赖 M0 骨架**([docs/arch/01-后端骨架与扩展规范.md](../arch/01-后端骨架与扩展规范.md))。
> M0 已落地可运行的 Walking Skeleton(空管线 + 接口 + 注册表 + 工程基线);本文的检测/策略/审计/评测等"真实现",应作为各能力的实现填入 `src/fulcrum/capabilities/` 等既有插槽,**不另起炉灶、不改核心管线**。

## Summary

MVP 目标是跑通一条可演示、可复现、可量化的智能体安全链路：

```
政务办公 Agent -> 枢衡 LLM 网关 -> 大模型
政务办公 Agent -> 枢衡工具网关 -> 文件 / HTTP / 命令工具
                         ↓
                    策略判定 / 阻断 / 审计 / 评测报告
```

MVP 不做完整安全中台,只做比赛最需要证明的闭环:

* 能识别文档/网页中的间接提示注入。
* 能拦截由不可信来源驱动的高危工具调用。
* 能记录审计证据和来源归因。
* 能扫描一个 MCP/Skill manifest 并给出供应链风险评级。
* 能用评测脚本输出 ASR、FPR、阻断率、审计完整率、溯源命中率等核心指标。

默认技术栈:

* Python 3.11
* uv
* FastAPI
* SQLite
* pytest
* ruff
* YAML 策略
* 命令行评测报告 + HTML/JSON 结果
* 暂不做完整 React 控制台

## Key Changes

### 1. 工程骨架

在 `src/fulcrum/` 下建立后端单体包,按能力分模块:

```
src/fulcrum/
├── gateway/        LLM 代理与工具代理
├── detectors/      输入风险检测与来源标注
├── policy/         YAML 策略解析与风险判定
├── toolguard/      工具调用风险评分与处置
├── sandbox/        受控执行器
├── supplychain/    manifest / Skill / MCP 最小扫描
├── audit/          SQLite 审计链与来源归因记录
├── eval/           样例回放、裁定器、指标计算
└── demo/           政务办公 Agent demo
```

新增工程配置:

* `pyproject.toml`: Python 3.11、依赖、ruff、pytest 配置。
* `.env.example`: 模型 endpoint、API key、数据库路径、策略路径。
* `scripts/eval.ps1`: Windows 评测入口。
* `scripts/demo.ps1`: 演示入口。
* `deploy/docker-compose.yml`: 后置,只在基础链路跑通后补。

### 2. MVP 数据模型

实现以下核心类型,优先用 `dataclass` 或 `pydantic`:

```
SourceSpan
- source_id
- source_type: user / document / webpage / retrieval / memory / tool_return / plugin_manifest
- trust_level: trusted / semi_trusted / untrusted
- content_hash
- excerpt
- risk_tags

ModelRequest
- request_id
- session_id
- messages
- sources

ToolIntent
- intent_id
- session_id
- tool_name
- arguments
- derived_from_sources
- risk_score

PolicyDecision
- decision: allow / sanitize / approve / block
- reason
- matched_policy_id
- risk_level

AuditEvent
- event_id
- session_id
- event_type
- subject_id
- decision
- evidence
- prev_hash
- event_hash

EvalSample
- sample_id
- scenario
- attack_type
- source_type
- input
- expected_action
- target_tool
- success_condition
- expected_trace_source
```

### 3. 接入链路

实现两个核心入口。

LLM Proxy:

```
POST /v1/chat/completions
```

行为:

* 接收 OpenAI-compatible chat completion 请求。
* 提取 messages 中的用户输入、文档片段、网页片段等来源。
* 给来源打 `SourceSpan`。
* 调用输入检测。
* 转发到真实模型 endpoint。
* 捕获模型输出和 tool_call。
* 将 tool_call 转为 `ToolIntent` 并交给策略判定。
* 写入审计事件。

MVP 可先支持非流式请求;流式响应放后置。

Tool Gateway:

```
POST /tools/call
```

请求:

```
{
  "session_id": "...",
  "tool_name": "file.read",
  "arguments": {},
  "source_ids": []
}
```

行为:

* 对工具名、参数、来源、会话轨迹做风险评分。
* 调用策略引擎得到 `allow / sanitize / approve / block`。
* `allow` 后进入受控执行器。
* `approve` 在 MVP 中记录为“需审批”,默认不执行。
* `block` 返回阻断原因。
* 全程写审计事件。

### 4. MVP 工具集

内置 4 个受控工具,足够覆盖演示和评测:

```
file.read
file.write
http.request
shell.exec
```

约束:

* `file.read` / `file.write` 只允许访问 demo workspace。
* `http.request` 默认只允许访问白名单域名;非白名单触发审批或阻断。
* `shell.exec` 默认 require_approval;危险命令直接 block。
* 所有工具调用都必须写审计事件。

### 5. 策略系统

使用 YAML 策略文件,默认放:

```
data/policies/default.yml
```

MVP 必须支持这些条件:

```
source_trust
tool_name
risk_level
path_matches
domain_allowed
command_risk
attribution_confidence
```

默认策略:

```
1. untrusted source 驱动 file.read / file.write / http.request -> block 或 approve
2. shell.exec 默认 require_approval
3. 涉密路径、key 文件、env 文件 -> block
4. http.request 非白名单域名 -> block
5. benign 低风险 file.read demo workspace -> allow
```

### 6. 输入检测与来源归因

MVP 不做复杂模型微调,先用可解释组合:

* 规则检测:忽略规则、泄露、读取敏感文件、外发、执行命令等关键词。
* 来源标注:用户、文档、网页、工具返回值都生成 `SourceSpan`。
* 简单归因:如果工具参数、路径、URL 或命令与不可信来源片段相似或同会话相邻,则建立 `derived_from_sources`。
* 归因置信度:规则命中 + 参数匹配 + 来源风险加权得到 0-1 分。

LLM judge 作为后置增强,不进入第一版 MVP 必需项。

### 7. 审计链

使用 SQLite 保存审计事件,默认路径:

```
data/runtime/fulcrum.sqlite
```

`.gitignore` 应保证 `data/runtime/` 不入库。

每个关键事件必须记录:

```
request_received
source_labeled
input_detected
model_forwarded
tool_intent_detected
policy_decided
tool_executed
tool_blocked
audit_written
eval_judged
```

审计事件用 hash-chain:

```
event_hash = sha256(prev_hash + canonical_json(event))
```

MVP 验收要求:

* 每个样例都能查到完整事件链。
* hash-chain 校验通过率 100%。

### 8. 供应链最小扫描

实现命令:

```
python -m fulcrum.supplychain scan samples/supplychain/*.json
```

支持扫描:

* MCP manifest
* Skill manifest
* 简单脚本元信息

MVP 检测项:

* 工具描述中是否包含提示注入语句。
* 权限是否包含文件、命令、网络等高危能力。
* 是否声明外联 URL。
* 是否包含可疑命令或下载行为。
* 输出 `allow / review / block` 评级。

不在 MVP 中实现真实 IDA/Ghidra/沙箱分析;保留为后续增强。

### 9. Demo Agent

实现一个极小政务办公 Agent demo,不用接复杂第三方 agent。

行为:

```
1. 读取一个“群众来信/政策材料”样例。
2. 调用 LLM 生成摘要。
3. 根据模型输出尝试调用 file.read 或 http.request。
4. 所有模型调用和工具调用都经过枢衡。
```

准备两条演示链路:

* 正常文档:生成摘要并读取允许目录文件,成功放行。
* 恶意文档:文档中藏“读取 secret 文件并外发”的间接注入,枢衡阻断并生成审计证据。

### 10. 评测引擎

实现统一入口:

```
python -m fulcrum.eval --dataset samples/eval/core.json --out docs/eval/results/latest
```

输出:

```
metrics.json
details.jsonl
report.html
```

MVP 样例集:

```
5 条 benign 正常任务
5 条 direct_prompt_injection
5 条 indirect_injection
3 条 unauthorized_tool
2 条 malicious_skill / manifest
```

核心指标:

* ASR_baseline
* ASR_fulcrum
* ASR 降幅
* BSR / Recall
* FPR
* Utility
* 高危动作处置正确率
* 审计完整率
* Source Hit@1 / @3
* 供应链恶意组件召回率

Baseline 方式:

* 同一 demo agent 绕过枢衡工具策略运行。
* 或使用 `--mode baseline` 禁用策略阻断,只记录攻击是否成功。

## Test Plan

### 单元测试

* `policy`: YAML 加载、规则匹配、优先级、allow/approve/block 判定。
* `detectors`: 注入关键词、来源标注、风险标签。
* `toolguard`: 文件路径、URL、命令风险评分。
* `audit`: hash-chain 写入和校验。
* `supplychain`: manifest 注入、高危权限、外联 URL 检测。
* `eval`: ASR/FPR/Recall/Utility/Source Hit 指标计算。

### 集成测试

* 正常文档链路:LLM 请求 -> 工具调用 -> allow -> 审计完整。
* 间接注入链路:不可信文档 -> 高危 file.read/http.request -> block -> 审计可溯源。
* shell.exec 链路:默认 require_approval,不实际执行危险命令。
* 供应链链路:恶意 manifest -> block/review 评级。
* eval 链路:跑 `samples/eval/core.json`,生成 `metrics.json` 和 `report.html`。

### 验收场景

MVP 完成时必须能演示:

```
1. 正常任务不被明显误伤。
2. 恶意文档诱导的高危工具调用被阻断。
3. 审计详情能说明:哪段输入 -> 哪次工具调用 -> 哪条策略 -> 什么处置。
4. 供应链扫描能识别一个恶意 MCP/Skill manifest。
5. 评测报告能展示 Baseline 与 Fulcrum 的 ASR 差异。
```

## Assumptions

* Python 固定使用 3.11,不要用系统默认 Python 3.14。
* MVP 使用自建极小政务办公 Agent,不先接 OpenHands/OpenManus 等复杂开源 agent。
* MVP 使用 SQLite,不先上 PostgreSQL/OTEL/Langfuse。
* MVP 不做完整 React 控制台,用 HTML/JSON 评测报告和 CLI 演示替代。
* MVP 不做真实恶意软件沙箱和 IDA/Ghidra 自动化,只做供应链 manifest/脚本元信息最小扫描。
* Docker Compose 可后置;本地开发先保证 `python -m ...` 和 `pytest` 可跑。
* 所有样例必须脱敏,不包含真实攻击目标、真实凭据、真实政企数据。
