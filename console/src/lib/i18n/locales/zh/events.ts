// 实时事件。
export const events = {
  'events.disp.block': '阻断',
  'events.disp.approve': '待审批',
  'events.disp.sanitize': '净化',
  'events.disp.allow': '放行',
  'events.level.critical': '严重',
  'events.level.high': '高',
  'events.level.medium': '中',
  'events.level.low': '低',
  'events.level_risk': '{level}风险',
  'events.filter.all': '全部',

  // 空态
  'events.empty.title': '还没有数据',
  'events.empty.hint': '导入备份后查看事件。',
  'events.none.title': '未选中事件',
  'events.none.hint': '从左侧清单选择一条以查看证据归因链',

  // 工具条
  'events.toolbar.filter': '筛选',
  'events.toolbar.group': '分组:处置',
  'events.toolbar.range': '近 24 小时',
  'events.toolbar.export': '导出报告',

  // 处置 toast
  'events.toast.allowed': '已批准放行',
  'events.toast.blocked': '已维持阻断',
  'events.toast.resolved_desc': '处置已记入审计链,该待审批项已结案。',
  'events.toast.resolve_failed': '处置失败',
  'events.toast.tamper_title': '审计链校验失败',
  'events.toast.tamper_desc': '会话 {sess} 的事件哈希与链不一致,疑似篡改,已锁定并上报。',

  // 详情头
  'events.detail.back': '返回列表',
  'events.detail.need_handle': '需要「处置会话事件」权限',
  'events.detail.approve': '批准放行',
  'events.detail.block': '维持阻断',
  'events.detail.full_chain': '查看完整链路',
  'events.detail.batch': '批量处置',
  'events.detail.prev': '上一条',
  'events.detail.next': '下一条',
  'events.detail.session': '会话',
  'events.detail.event': '事件',

  // 详情字段
  'events.field.source': '来源',
  'events.field.tool': '工具/动作',
  'events.field.policy': '命中策略',
  'events.field.conf': '置信度',
  'events.field.time': '时间',

  // 对话
  'events.conv.title': '对话',
  'events.conv.masked': '已脱敏',
  'events.conv.empty': '本事件为工具调用治理,无对话上下文。',
  'events.conv.user': '用户',
  'events.conv.ai': 'AI 智能体',
  'events.conv.current': '当前',
  'events.conv.collapse': '收起对话',
  'events.conv.expand': '查看完整对话(共 {count} 条)',

  // 证据归因链
  'events.chain.title': '证据归因链',
  'events.chain.source': '来源片段',
  'events.chain.intent': '模型意图',
  'events.chain.args': '工具参数',
  'events.chain.derived': '证据化归因',
  'events.chain.policy': '命中策略',
  'events.chain.disposition': '处置',
  'events.chain.hashchain': '审计 hash-chain',
  'events.chain.none': '无',
  'events.chain.conf': '置信度 {conf}',
  'events.chain.verified': '链校验通过 · 5 个事件连续',
  'events.chain.tamper_title': '审计链校验失败',
  'events.chain.tamper_desc': '事件 #4 哈希与 prev 不一致,疑似篡改。已锁定会话并上报取证。',
} as const
