# 枢衡攻击样例库 · 分类法映射(TAXONOMY)

> 每条样本挂标准分类 ID,对标杀软"特征挂 CVE/MITRE"做法。ID 经权威源核对(2026-06)。

## 1. OWASP Top 10 for LLM Applications — 2025
| ID | 标题 |
|---|---|
| LLM01:2025 | Prompt Injection |
| LLM02:2025 | Sensitive Information Disclosure |
| LLM03:2025 | Supply Chain |
| LLM04:2025 | Data and Model Poisoning |
| LLM05:2025 | Improper Output Handling |
| LLM06:2025 | Excessive Agency |
| LLM07:2025 | System Prompt Leakage |
| LLM08:2025 | Vector and Embedding Weaknesses |
| LLM09:2025 | Misinformation |
| LLM10:2025 | Unbounded Consumption |

源:https://genai.owasp.org/llm-top-10/

## 2. MITRE ATLAS(AI 威胁矩阵)
| ID | 名称 |
|---|---|
| AML.T0051 / .000 / .001 | LLM Prompt Injection / Direct / Indirect |
| AML.T0054 | LLM Jailbreak |
| AML.T0056 | Extract LLM System Prompt |
| AML.T0010 / .001 | AI Supply Chain Compromise / AI Software |
| AML.T0020 | Poison Training Data |
| AML.T0070 | RAG Poisoning |
| AML.T0024 | Exfiltration via AI Inference API |
| AML.T0015 | Evade AI Model |

源:https://github.com/mitre-atlas/atlas-data 。注:ATLAS 无"插件/工具"专属技术,供应链统一映射 T0010.001。

## 3. CWE(弱点分类)
| ID | 标题 |
|---|---|
| CWE-1427 | Improper Neutralization of Input Used for LLM Prompting |
| CWE-22 | Path Traversal |
| CWE-918 | Server-Side Request Forgery (SSRF) |
| CWE-78 | OS Command Injection |
| CWE-94 | Code Injection |
| CWE-200 | Exposure of Sensitive Information |
| CWE-522 | Insufficiently Protected Credentials(读凭据文件) |
| CWE-532 | Insertion of Sensitive Information into Log |

源:https://cwe.mitre.org/

## 4. MITRE ATT&CK(工具/命令层)
| ID | 名称 |
|---|---|
| T1059 / .001 / .004 | Command and Scripting Interpreter / PowerShell / Unix Shell |
| T1218 / .005 / .010 / .011 | System Binary Proxy Execution / Mshta / Regsvr32 / Rundll32 |
| T1105 | Ingress Tool Transfer |
| T1140 | Deobfuscate/Decode Files or Information |
| T1047 | Windows Management Instrumentation |
| T1003 / .001 / .002 / .003 | OS Credential Dumping / LSASS / SAM / NTDS |
| T1552 / .005 | Unsecured Credentials / Cloud Instance Metadata API |
| T1567 / T1041 | Exfiltration Over Web Service / C2 Channel |
| T1053.005 | Scheduled Task |
| T1070.001 | Indicator Removal: Clear Windows Event Logs |
| T1197 | BITS Jobs |

源:https://attack.mitre.org/

## 5. 攻击面 → 分类映射(贴标规则,见 `_stamp` 逻辑)
| 攻击面(technique 前缀) | OWASP | ATLAS | ATT&CK | CWE |
|---|---|---|---|---|
| `inject.*` / `encoding.*` / `unicode.*` | LLM01/02/07 | AML.T0051.000 | — | CWE-1427 |
| `indirect.*` | LLM01/02/06 | AML.T0051.001 | — | CWE-1427 |
| `jailbreak.*` | LLM01/07 | AML.T0054 | — | CWE-1427 |
| `poison.*`(rag→T0070) | LLM04/08 | AML.T0020 / T0070 | — | (embedded→1427) |
| `supplychain.*` | LLM03 | AML.T0010.001 | — | (exec→CWE-94) |
| `file.sensitive.*` | LLM06 | — | T1003.*/T1552 | CWE-522 |
| `path.traversal.*` | LLM06 | — | — | CWE-22 |
| `ssrf.*`(metadata→.005) | LLM06 | — | T1552.005 | CWE-918 |
| `cmd.*` | LLM06 | — | T1059/T1218/T1003/… | CWE-78 |
| `exfil.egress.*` | LLM02 | AML.T0024 | T1567 | CWE-200 |
| `egress.*`(sysprompt→T0056) | LLM02/07/09 | AML.T0024 / T0056 | — | CWE-200/532 |
| `agency.*` | LLM06 | — | — | — |
| `benign.*` | — | — | — | — |
