// 供应链页类型 —— 结构镜像后端 ScanReport(ManifestScanner,`python -m fulcrum.scan`)。
// 评级:critical→block / high→approve / medium→sanitize / 否则 allow。
// 数据走真后端 /supply/scans;离线预览的演示数据经备份系统载入(public/demo-backup.json),不在此硬编码。

export type Rating = 'block' | 'approve' | 'sanitize' | 'allow'
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
  risks: ScanRisk[]
}
