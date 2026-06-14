/** 备份文件元信息 */
export interface BackupMeta {
  exportedAt?: string
  instance?: string
  note?: string
  appVersion?: string
}

/**
 * 枢衡备份文件:版本化、按资源类型分桶的容器。
 * 现在只有 events,未来可加 policies / tools / supplyChain / auditChains / evalRuns / settings …
 * 加新资源**不改这个结构**,只在注册表里注册一种新 resource。
 */
export interface BackupFile {
  kind: 'fulcrum.backup'
  schemaVersion: number
  meta: BackupMeta
  resources: Record<string, unknown[]>
}

/** 解析后的资源数据:kind -> 该类资源的数组 */
export type ResourceData = Record<string, unknown[]>
