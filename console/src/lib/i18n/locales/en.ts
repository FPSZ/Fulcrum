import type { MessageKey } from '../index'

/**
 * 英文词典(占位)—— 现阶段词典先只填中文(plan 决策:先让代码可 i18n)。
 * 这里是 `Partial`:缺项自动回退 `zh` 真源。要上英文时按 `MessageKey` 逐条补译即可,
 * 补一条即生效,无需改任何调用点。
 */
export const en: Partial<Record<MessageKey, string>> = {
  // 示例(后续补全):
  // 'common.save': 'Save',
  // 'auth.login': 'Sign in',
}
