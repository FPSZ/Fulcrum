/**
 * 英文词典 —— `Partial`(可逐步补,缺项自动回退中文真源 `zh`)。
 * 结构镜像 `zh/`:按功能域分文件后在此汇总。新增 key 先进 `zh`(真源),英文按需补译。
 */
import type { MessageKey } from '../../index'
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

export const en: Partial<Record<MessageKey, string>> = {
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
