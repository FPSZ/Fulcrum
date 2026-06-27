/**
 * 中文词典 —— i18n **真源**(永远完整)。`MessageKey = keyof typeof zh`,写错 key 即编译失败。
 *
 * 约定:key 用 `<域>.<子项>` 扁平命名(`common.*` 跨页复用;`auth.*`/`roles.*`… 按功能域)。
 * 文案里 `{name}` 为占位,调用 `t('k', { name })` 替换。新页迁移时把硬编码搬来此处、加 key。
 */
export const zh = {
  // ── 通用(跨页复用)──────────────────────────────────────────
  'common.save': '保存',
  'common.cancel': '取消',
  'common.confirm': '确定',
  'common.delete': '删除',
  'common.edit': '编辑',
  'common.close': '关闭',
  'common.back': '返回',
  'common.loading': '加载中…',
  'common.app.name': '枢衡',
  'common.app.tagline': '智能体安全中台',

  // ── 登录 / 账号申请 ─────────────────────────────────────────
  'auth.welcome': '欢迎回来',
  'auth.login': '登录',
  'auth.logging_in': '正在登录…',
  'auth.field.account': '账号',
  'auth.field.account_ph': '请输入账号',
  'auth.field.password': '口令',
  'auth.field.password_ph': '请输入口令',
  'auth.remember': '记住登录',
  'auth.forgot': '忘记口令?',
  'auth.pwd.show': '显示口令',
  'auth.pwd.hide': '隐藏口令',
  'auth.no_account': '没有账号?',
  'auth.have_account': '已有账号?',
  'auth.apply_account': '申请账号',
  'auth.back_to_login': '返回登录',
  'auth.apply_hint': '提交后由管理员审批,通过后即可登录。',
  'auth.apply_submit': '提交申请',
  'auth.submitting': '提交中…',
  'auth.field.name': '姓名',
  'auth.field.name_ph': '请输入真实姓名',
  'auth.field.account_apply_ph': '用于登录的账号',
  'auth.field.pwd_min_ph': '至少 8 位',
  'auth.field.confirm_pwd': '确认口令',
  'auth.field.confirm_pwd_ph': '再次输入口令',
  'auth.apply.submitted': '申请已提交',
  'auth.apply.submitted_hint': '请等待管理员审批,通过后即可使用该账号登录。',
  'auth.error.login_failed': '登录失败',
  'auth.error.apply_failed': '申请失败',
  'auth.error.name_account_required': '请填写姓名与账号',
  'auth.error.pwd_min': '口令至少需要 8 位',
  'auth.error.pwd_mismatch': '两次输入的口令不一致',
} as const
