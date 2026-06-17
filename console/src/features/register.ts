import { registerFeature, type FeatureModule } from '@/lib/module'
import { registerResource } from '@/lib/backup'
import { eventsModule } from './events/module'
import { overviewModule } from './overview/module'
import { settingsModule } from './settings/module'
import { usersModule } from './admin/module'
import { policiesModule } from './policies/module'
import { auditModule } from './audit/module'
import { evalModule } from './eval/module'
import { toolsModule } from './tools/module'
import { supplyModule } from './supply/module'

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
  usersModule,
  settingsModule,
]

export function registerFeatures(): void {
  for (const m of FEATURES) {
    registerFeature(m)
    m.resources?.forEach(registerResource)
  }
}
