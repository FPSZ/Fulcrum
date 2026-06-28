// 审计溯源页。
export const audit = {
  'audit.empty.title': '暂无审计会话',
  'audit.empty.hint': '安全网关处理请求后即生成审计链。也可在「数据与备份」载入演示备份预览。',

  'audit.chain_intact': '链完整',
  'audit.tampered': '已篡改',
  'audit.verify_pass': 'Hash-chain 校验通过',
  'audit.verify_fail': '校验失败,疑似篡改',
  'audit.event_count': '{count} 个事件',

  'audit.disp.block': '阻断',
  'audit.disp.approve': '审批',
  'audit.disp.sanitize': '净化',
  'audit.disp.allow': '放行',

  'audit.event.request_received': '收到请求',
  'audit.event.source_labeled': '来源打标',
  'audit.event.input_detected': '输入检测',
  'audit.event.model_forwarded': '转发模型',
  'audit.event.tool_intent_detected': '工具意图',
  'audit.event.policy_decided': '策略判定',
  'audit.event.tool_executed': '工具执行',
  'audit.event.tool_blocked': '工具阻断',
  'audit.event.tool_pending_approval': '挂起审批',
} as const
