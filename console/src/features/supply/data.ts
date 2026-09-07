// 供应链页类型 —— 结构镜像后端 ScanReport(ManifestScanner,`python -m fulcrum.scan`)。
// 评级:critical→block / high→approve / medium→sanitize / 否则 allow。
// 数据走真后端 /supply/scans;离线预览的演示数据经备份系统载入(public/demo-backup.json),不在此硬编码。

import type { Disposition } from '@/lib/disposition'

// 评级与处置同值域(后端 ScanReport.rating 即 Disposition);单一真源在 @/lib/disposition(M29)。
export type Rating = Disposition
export type Severity = 'critical' | 'high' | 'medium' | 'low'

export interface ScanRisk {
  kind: string
  score: number
  severity: Severity
  detail: string
}

export interface ScanReport {
  component_id: string
  kind: string
  rating: Rating
  description?: string // manifest 自报描述(中文可读,便于识别);备份演示数据可缺省
  risks: ScanRisk[]
}
