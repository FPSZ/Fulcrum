// AI 操作助手。
export const assistant = {
  // 空态(hero)
  'assistant.hero.title': '需要我帮你做点什么?',
  'assistant.cap.query': '数据查询',
  'assistant.cap.handle': '业务办理',
  'assistant.cap.navigate': '页面跳转',
  'assistant.cap.settings': '更改设置',
  // 空态建议
  'assistant.suggest.overview': '看一下安全总览',
  'assistant.suggest.events': '最近有哪些被拦截的事件?',
  'assistant.suggest.approvals': '列出待审批的账号',
  'assistant.suggest.gateway': '把上游网关名称改一下',
  // 底部提示
  'assistant.disclaimer': 'AI 可能出错,请核对结果',

  // 输入框
  'assistant.composer.placeholder': '给助手下达任务…',
  'assistant.composer.send': '发送',
  'assistant.composer.stop': '停止生成',
  'assistant.composer.hint.ready': 'Enter 发送 · Shift+Enter 换行',
  'assistant.composer.hint.unconfigured': '模型未配置 · 点左侧设置',
  'assistant.composer.hint.contact_admin': '模型未配置 · 请联系管理员',
  'assistant.composer.settings': '模型设置',
  'assistant.composer.settings.configure': '模型未配置 —— 点击配置',
  'assistant.composer.settings.no_perm': '模型设置(需权限)',
  'assistant.composer.settings.no_perm_title': '配置模型需相应权限,请联系管理员',

  // 会话侧栏
  'assistant.sidebar.title': '会话',
  'assistant.sidebar.expand': '展开会话栏',
  'assistant.sidebar.collapse': '收起会话栏',
  'assistant.sidebar.new': '新建会话',
  'assistant.sidebar.history': '历史会话',
  'assistant.sidebar.empty': '暂无历史会话',
  'assistant.sidebar.empty.hint': '开始对话即在此留存',
  'assistant.sidebar.untitled': '新对话',
  'assistant.sidebar.delete': '删除会话',

  // 消息回合
  'assistant.turn.blocked': '已被安全网关拦截',
  'assistant.turn.trace': '执行过程 · {n} 步',
  'assistant.turn.error': '出错:{msg}',
  'assistant.turn.stopped': '(已停止生成)',

  // 上下文压缩提示
  'assistant.compress.title': '已自动压缩较早的上下文',
  'assistant.compress.desc': '对话较长,已把更早的内容压成摘要以延续上下文。',

  // 导航指令反馈
  'assistant.nav.events': '已切到实时事件',
  'assistant.nav.settings': '已打开系统设置',
  'assistant.nav.opened': '已为你打开「{label}」',

  // 模型未配置拦截
  'assistant.model.unconfigured': '模型尚未配置',
  'assistant.model.unconfigured.configure': '请先在设置里配置模型协议、端点与密钥。',
  'assistant.model.unconfigured.contact': '请联系管理员配置 AI 模型接入后再使用。',

  // 提案卡(写操作)
  'assistant.proposal.confirm': '确认执行',
  'assistant.proposal.executing': '执行中…',
  'assistant.proposal.cancelled': '已取消',
  'assistant.proposal.undo': '撤销',
  'assistant.proposal.undo_with': '撤销({preview})',
  'assistant.proposal.done': '已执行',
  'assistant.proposal.undoing': '撤销中…',
  'assistant.proposal.undone': '已撤销',
  'assistant.proposal.bool.yes': '是',
  'assistant.proposal.bool.no': '否',

  // 提案执行结果(toast)
  'assistant.toast.executed': '已执行',
  'assistant.toast.execute_failed': '执行未成功',
  'assistant.toast.undone': '已撤销',
  'assistant.toast.undo_failed': '撤销未成功',

  // 审批卡
  'assistant.approval.badge': '需管理员审批',
  'assistant.approval.reason': '审批理由',
  'assistant.approval.reason.placeholder': '说明为什么需要执行这一步,管理员据此审批…',
  'assistant.approval.file': '发起审批申请',
  'assistant.approval.retry': '重试发起',
  'assistant.approval.skip_hint': '不发起则不留工单',
  'assistant.approval.filing': '发起中…',
  'assistant.approval.filed': '已进入待审批,管理员处理中',
  // 审批申请结果(toast)
  'assistant.approval.toast.filed': '已发起审批申请',
  'assistant.approval.toast.filed_desc': '已进入「实时事件 · 待审批」,管理员将在那里处理。',
  'assistant.approval.toast.failed': '发起失败',

  // 模型设置弹窗
  'assistant.settings.title': 'AI 模型接入',
  'assistant.settings.readonly': '你没有配置权限,以下为只读。请联系超级管理员或系统管理员配置。',
  'assistant.settings.protocol': '协议',
  'assistant.settings.preset': '快速预设',
  'assistant.settings.preset.local': '本地',
  'assistant.settings.endpoint': '端点 Endpoint',
  'assistant.settings.model': '模型名 Model',
  'assistant.settings.api_key': 'API Key(本地模型可留空)',
  'assistant.settings.api_key.ph_local': '本地模型可留空',
  'assistant.settings.api_key.ph_set': '已配置 {masked}(留空保持不变)',
  'assistant.settings.timeout': '超时(秒)',
  'assistant.settings.verify_tls': '校验 TLS 证书',
  'assistant.settings.test': '测试连接',
  // 协议元信息
  'assistant.settings.endpoint.ph_openai': 'https://api.openai.com/v1 或 http://127.0.0.1:1234/v1',
  'assistant.settings.proto.openai': 'OpenAI 兼容',
  'assistant.settings.proto.openai.hint': '覆盖 OpenAI / DeepSeek / Kimi / MiMo,以及本地 vLLM / LM Studio / llama.cpp / Ollama 的 /v1 端点',
  'assistant.settings.proto.ollama': 'Ollama 原生',
  'assistant.settings.proto.ollama.hint': '本地私有化最常见,通常免密钥',
  'assistant.settings.proto.anthropic': 'Anthropic',
  'assistant.settings.proto.anthropic.hint': 'Claude /v1/messages',
  // 保存结果(toast)
  'assistant.settings.toast.saved': '已保存模型配置',
  'assistant.settings.toast.saved_desc': '热加载生效,现在可以开始对话了。',
  'assistant.settings.toast.save_failed': '保存失败',

  // 流式请求失败
  'assistant.error.request_failed': '助手请求失败',

  // 风险分级
  'assistant.risk.read_only': '只读',
  'assistant.risk.normal': '一般',
  'assistant.risk.high': '高危',

  // 工具类别(轨迹标签 / 侧栏分组)
  'assistant.kind.ui': '界面',
  'assistant.kind.read': '查询',
  'assistant.kind.write': '操作',

  // 快捷示例意图
  'assistant.intent.overview': '帮我打开安全总览',
  'assistant.intent.blocked_events': '只看被阻断的实时事件',
  'assistant.intent.disable_policy': '临时停用策略 POL-014',
} as const
