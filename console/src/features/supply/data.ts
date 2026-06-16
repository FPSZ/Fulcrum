// 供应链页数据 —— 结构镜像后端 ScanReport(ManifestScanner,`python -m fulcrum.scan`)。
// 评级:critical→block / high→approve / medium→sanitize / 否则 allow。
// 当前为代表性 seed(取 samples/supplychain 真实扫描输出);后续接扫描 API 时换数据源即可。

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

export const SCAN_REPORTS: ScanReport[] = [
  {
    component_id: 'super-helper-plugin@0.0.7',
    kind: 'plugin',
    rating: 'block',
    risks: [
      { kind: 'perm.command_exec', score: 0.9, severity: 'critical', detail: '声明高危权限:shell.exec' },
      { kind: 'perm.credential_access', score: 0.9, severity: 'critical', detail: '声明高危权限:read_credentials' },
      { kind: 'desc.suspicious', score: 0.9, severity: 'critical', detail: "描述含可疑意图关键词:['反弹 shell', '后门', '隐蔽外联']" },
      { kind: 'perm.file_write', score: 0.7, severity: 'high', detail: '声明高危权限:file.write' },
      { kind: 'endpoint.raw_ip', score: 0.7, severity: 'high', detail: '外联裸 IP:http://203.0.113.66:8080/collect' },
      { kind: 'dep.install_from_url', score: 0.7, severity: 'high', detail: '从 URL/源码直接安装依赖:git+http://198.51.100.7/payload.git' },
      { kind: 'endpoint.suspicious_host', score: 0.5, severity: 'medium', detail: '可疑外联域名:https://exfil.duckdns.org/upload' },
      { kind: 'perm.network', score: 0.3, severity: 'low', detail: '声明高危权限:network' },
    ],
  },
  {
    component_id: 'log-forwarder-skill@2.1.0',
    kind: 'skill',
    rating: 'approve',
    risks: [
      { kind: 'perm.file_write', score: 0.7, severity: 'high', detail: '声明高危权限:file.write' },
      { kind: 'endpoint.plaintext_http', score: 0.5, severity: 'medium', detail: '明文 http 外联:http://logs.internal/collect' },
      { kind: 'perm.network', score: 0.3, severity: 'low', detail: '声明高危权限:network' },
    ],
  },
  {
    component_id: 'weather-query-skill@1.2.0',
    kind: 'skill',
    rating: 'allow',
    risks: [
      { kind: 'perm.file_read', score: 0.3, severity: 'low', detail: '声明高危权限:file.read' },
      { kind: 'perm.network', score: 0.3, severity: 'low', detail: '声明高危权限:network' },
    ],
  },
  {
    component_id: 'gov-notice-mcp@0.4.2',
    kind: 'mcp',
    rating: 'allow',
    risks: [{ kind: 'perm.network', score: 0.3, severity: 'low', detail: '声明高危权限:network' }],
  },
]
