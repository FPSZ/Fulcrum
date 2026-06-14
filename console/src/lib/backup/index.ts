export { registerResource, getResourceSpec, getResourceSpecs, type ResourceSpec } from './registry'
export { parseBackup, buildBackup, BACKUP_SCHEMA_VERSION, type ImportReport } from './io'
export { BackupProvider, useBackup, useResource } from './context'
export type { BackupFile, BackupMeta, ResourceData } from './types'
