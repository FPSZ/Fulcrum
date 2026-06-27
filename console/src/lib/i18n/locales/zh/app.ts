// app —— 应用外壳(顶栏 / 侧栏 / 抽屉 / 页脚 / 占位)。
export const app = {
  // 页脚
  'app.footer.tagline': '面向政企场景的大模型智能体安全中台',
  'app.footer.contact': 't. 智能体调用 · 实时管控 · 全链路审计',
  'app.footer.nav': '导航 / Navigation',
  'app.footer.nav.overview': '总览',
  'app.footer.nav.events': '事件',
  'app.footer.nav.users': '用户',
  'app.footer.nav.settings': '设置',
  'app.footer.legal.privacy': '隐私政策',
  'app.footer.legal.terms': '服务条款',
  'app.footer.legal.compliance': '合规说明',
  'app.footer.legal.license': '开源许可',
  'app.footer.rights': '© 2026 枢衡 Fulcrum · 保留所有权利',
  'app.footer.back_to_top': '回到顶部',
  'app.footer.email': '邮件',

  // 顶栏
  'app.topbar.menu': '打开菜单',
  'app.topbar.expand_sidebar': '展开侧栏',
  'app.topbar.collapse_sidebar': '收起侧栏',
  'app.topbar.search': '检索',
  'app.topbar.search_placeholder': '检索事件 / 会话 / trace_id…',
  'app.topbar.switch_bg': '切换背景 · {name}',
  'app.topbar.help': '帮助',
  'app.topbar.alerts': '告警',

  // 抽屉
  'app.drawer.close': '关闭菜单',

  // 侧栏
  'app.sidebar.signed_out': '未登录',
  'app.sidebar.assist.title': 'AI 安全研判',
  'app.sidebar.assist.open': '打开研判台',
  'app.sidebar.logout': '退出登录',
  // 导航分组(键为 lib/module 的分组内部值)
  'app.sidebar.group.监测': '监测',
  'app.sidebar.group.管控': '管控',
  'app.sidebar.group.取证': '取证',
  'app.sidebar.group.系统': '系统',

  // 占位 / 外壳
  'app.shell.console': '控制台',
  'app.placeholder.title': '{title} · 建设中',
  'app.placeholder.hint': '该模块将在后续版本接入',

  // 导航(各功能页显示名,与 module.tsx 的 labelKey 对应)
  'app.nav.overview': '安全总览',
  'app.nav.gateway': '网关实测',
  'app.nav.events': '实时事件',
  'app.nav.assistant': '操作助手',
  'app.nav.policies': '策略中心',
  'app.nav.tools': '工具网关',
  'app.nav.supply': '供应链',
  'app.nav.audit': '审计溯源',
  'app.nav.eval': '评测验证',
  'app.nav.members': '组织与成员',
  'app.nav.settings': '系统设置',
} as const
