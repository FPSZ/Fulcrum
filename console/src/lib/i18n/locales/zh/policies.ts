// 策略中心页。
export const policies = {
  'policies.empty.title': '暂无装配策略',
  'policies.empty.hint': '策略来自后端当前加载的配置。请确认安全网关后端在运行。',

  'policies.default': '默认处置',
  'policies.workspace': '工作区',
  'policies.allow_domains': '外联白名单',
  'policies.version': '规则集 v{version}',
  'policies.rule_count': '{count} 条规则',
  'policies.condition_hit': '条件命中',

  'policies.filter.all': '全部',
  'policies.filter.block': '阻断',
  'policies.filter.approve': '审批',

  'policies.disp.block': '阻断',
  'policies.disp.approve': '审批',
  'policies.disp.sanitize': '净化',
  'policies.disp.allow': '放行',
} as const
