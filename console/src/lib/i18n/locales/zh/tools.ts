// 工具网关页。
export const tools = {
  'tools.empty.title': '暂无工具调用',
  'tools.empty.hint': '工具调用穿过枢衡即在此显示。也可在「数据与备份」载入演示备份预览。',
  'tools.execute.tool': '工具名',
  'tools.execute.arguments': '参数 JSON',
  'tools.execute.propose': '创建提案',
  'tools.execute.confirm': '确认执行',
  'tools.execute.invalid_args': '参数必须是 JSON 对象。',
  'tools.execute.failed': '工具调用请求失败。',

  'tools.summary': '近 {total} 次调用,其中 {held} 次被管控(阻断 / 审批)',

  'tools.filter.all': '全部',
  'tools.filter.held': '已管控',
  'tools.filter.allow': '放行',

  'tools.col.time': '时间',
  'tools.col.tool': '工具 · 参数',
  'tools.col.source': '来源',
  'tools.col.risk': '风险',
  'tools.col.attribution': '归因',
  'tools.col.disposition': '处置',

  'tools.disp.block': '阻断',
  'tools.disp.approve': '审批',
  'tools.disp.sanitize': '净化',
  'tools.disp.allow': '放行',

  'tools.trust.untrusted': '不可信',
  'tools.trust.semi': '半可信',
  'tools.trust.trusted': '可信',
} as const
