// 策略中心类型 —— 结构镜像后端 data/policies/*.yml(YamlPolicyEngine 加载的声明式策略)。
// 数据走真后端 /policies(后端在跑即非空);不在此硬编码 seed。

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
