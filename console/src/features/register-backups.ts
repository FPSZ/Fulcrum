import { registerResource } from '@/lib/backup'
import { eventResourceSpec } from './events/backup'

/**
 * 注册所有可导入/导出的资源。
 * 备份系统持续扩展:以后新增 policies / tools / supplyChain / evalRuns … 时,
 * 在各自 feature 里写一个 ResourceSpec,然后在这里加一行 registerResource() 即可。
 */
export function registerBackupResources(): void {
  registerResource(eventResourceSpec)
  // registerResource(policyResourceSpec)
  // registerResource(toolResourceSpec)
  // …
}
