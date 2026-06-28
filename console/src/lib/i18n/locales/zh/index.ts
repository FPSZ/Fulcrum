/**
 * 中文词典 —— i18n **真源**(永远完整),按功能域分文件后在此汇总。
 * `MessageKey = keyof typeof zh` 由它派生 → 写错 key 即编译失败。
 *
 * 约定:key 用 `<域>.<子项>` 扁平命名(`common.*` 跨页复用;其余按功能域)。
 * 文案里 `{name}` 为占位,调用 `t('k', { name })` 替换。新页迁移:把硬编码搬进对应域文件、加 key。
 */
import { admin } from './admin'
import { app } from './app'
import { assistant } from './assistant'
import { audit } from './audit'
import { auth } from './auth'
import { backup } from './backup'
import { common } from './common'
import { evalDict } from './eval'
import { events } from './events'
import { gateway } from './gateway'
import { lib } from './lib'
import { overview } from './overview'
import { policies } from './policies'
import { settings } from './settings'
import { supply } from './supply'
import { tools } from './tools'
import { ui } from './ui'

export const zh = {
  ...common,
  ...auth,
  ...settings,
  ...overview,
  ...events,
  ...gateway,
  ...tools,
  ...supply,
  ...audit,
  ...evalDict,
  ...policies,
  ...admin,
  ...assistant,
  ...backup,
  ...ui,
  ...app,
  ...lib,
}
