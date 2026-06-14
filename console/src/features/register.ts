import { registerFeature, type FeatureModule } from '@/lib/module'
import { registerResource } from '@/lib/backup'
import { eventsModule } from './events/module'
import { settingsModule } from './settings/module'
import {
  auditModule,
  evalModule,
  overviewModule,
  policiesModule,
  supplyModule,
  toolsModule,
} from './placeholders'

/**
 * 唯一的"装配清单" —— 类似后端 load_builtin_capabilities()。
 * 新增页面只需:写好模块,在这里加一行。导航 / 路由 / 备份资源自动接上。
 */
const FEATURES: FeatureModule[] = [
  overviewModule,
  eventsModule,
  policiesModule,
  toolsModule,
  supplyModule,
  auditModule,
  evalModule,
  settingsModule,
]

export function registerFeatures(): void {
  for (const m of FEATURES) {
    registerFeature(m)
    m.resources?.forEach(registerResource)
  }
}
