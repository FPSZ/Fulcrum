// 策略中心数据 —— 结构镜像后端 data/policies/*.yml(YamlPolicyEngine 加载的声明式策略)。
// 当前为代表性 seed(取 gov_demo.yml);后续接策略读取 API / 备份资源时换数据源即可。

export type Disposition = 'block' | 'approve' | 'sanitize' | 'allow'
export type RiskLevel = 'critical' | 'high' | 'medium' | 'low'

export interface PolicyRule {
  id: string
  /** when 条件(扁平 key→展示值),与 yaml_policy._PREDICATES 对齐 */
  when: { key: string; value: string }[]
  decision: Disposition
  risk_level: RiskLevel
  reason: string
}

export interface PolicySet {
  name: string
  version: number
  default: Disposition
  workspace: string
  allow_domains: string[]
  rules: PolicyRule[]
}

export const POLICY_SET: PolicySet = {
  name: '政务大厅智能助手 · 演示策略',
  version: 1,
  default: 'allow',
  workspace: 'data/gov_workspace',
  allow_domains: ['gov.cn', 'xiongan.gov.cn'],
  rules: [
    {
      id: 'block-exfil-chain',
      when: [{ key: 'chain_risk_at_least', value: '0.8' }],
      decision: 'block',
      risk_level: 'critical',
      reason: '检测到「敏感数据读取 → 对外发送」异常动作链,疑似数据外泄',
    },
    {
      id: 'approve-readsend-chain',
      when: [{ key: 'chain_risk_at_least', value: '0.4' }],
      decision: 'approve',
      risk_level: 'high',
      reason: '检测到「读取 → 对外发送」动作链,须人工复核',
    },
    {
      id: 'block-confidential-doc',
      when: [
        { key: 'tool_in', value: 'doc.read, file.read' },
        { key: 'path_sensitive', value: 'true' },
      ],
      decision: 'block',
      risk_level: 'critical',
      reason: '该资料为机密级,禁止智能体读取',
    },
    {
      id: 'block-untrusted-highrisk',
      when: [
        { key: 'source_trust', value: 'untrusted' },
        { key: 'risk_at_least', value: '0.6' },
      ],
      decision: 'block',
      risk_level: 'high',
      reason: '不可信来源驱动的高危业务动作(疑似间接指令注入)',
    },
    {
      id: 'block-external-exfil',
      when: [
        { key: 'tool_in', value: 'external.send' },
        { key: 'domain_allowed', value: 'false' },
      ],
      decision: 'block',
      risk_level: 'critical',
      reason: '目标地址不在外联白名单,疑似数据外泄',
    },
    {
      id: 'block-dangerous-command',
      when: [
        { key: 'tool_in', value: 'shell.exec' },
        { key: 'command_dangerous', value: 'true' },
      ],
      decision: 'block',
      risk_level: 'critical',
      reason: '命令包含高危操作',
    },
    {
      id: 'approve-funds',
      when: [{ key: 'tool_in', value: 'funds.disburse' }],
      decision: 'approve',
      risk_level: 'high',
      reason: '发放财政补助资金,须经人工审批',
    },
    {
      id: 'approve-case',
      when: [{ key: 'tool_in', value: 'case.approve' }],
      decision: 'approve',
      risk_level: 'high',
      reason: '低保/救助审批为关键业务决定,须经人工复核',
    },
    {
      id: 'approve-shell',
      when: [{ key: 'tool_in', value: 'shell.exec' }],
      decision: 'approve',
      risk_level: 'high',
      reason: '系统命令默认需人工审批',
    },
  ],
}
