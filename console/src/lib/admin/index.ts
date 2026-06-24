/**
 * 管理后台 API 客户端(组织 / 角色 / 成员 / 权限)。
 * 请求封装复用同源基座 {@link api}(会话 Cookie 自动携带,非 2xx 抛后端 detail)。
 */

import { api, j, patch } from '@/lib/api/client'

export interface PermissionDef {
  key: string
  label: string
  group: string
  capability: string // 能力域 id(成对看/改共享 → 合成只读/读写三态)
  cap_label: string // 能力域中文名(展示一行)
  access: 'read' | 'write' | 'action'
}

export interface Department {
  id: number
  name: string
  parent_id: number | null
  sort_order: number
  member_count: number
}

export interface Role {
  id: number
  key: string
  name: string
  description: string
  is_system: boolean
  permissions: string[]
  member_count: number
  scope: 'org' | 'team' // 组织级(全局)| 团队级(团队内模板)
}

export type UserStatus = 'pending' | 'active' | 'disabled' | 'left'

export interface Member {
  id: number
  username: string
  display_name: string
  status: UserStatus
  employee_no: string
  email: string
  phone: string
  title: string
  department_id: number | null
  role_id: number | null
  created_at: number
  last_login_at: number | null
}

export interface TempPasswordResult {
  user: Member
  temp_password: string | null
}

// ── 权限目录 ────────────────────────────────────────────────────
export const listPermissions = () => api<PermissionDef[]>('/admin/permissions')

// ── 组织架构 ────────────────────────────────────────────────────
export const listDepartments = () => api<Department[]>('/admin/departments')
export const createDepartment = (b: { name: string; parent_id: number | null }) =>
  api<Department>('/admin/departments', j(b))
export const updateDepartment = (
  id: number,
  b: { name?: string; parent_id?: number | null; sort_order?: number },
) => api<Department>(`/admin/departments/${id}`, patch(b))
export const deleteDepartment = (id: number) =>
  api<void>(`/admin/departments/${id}`, { method: 'DELETE' })

// ── 角色 ────────────────────────────────────────────────────────
export const listRoles = () => api<Role[]>('/admin/roles')
export const createRole = (b: { name: string; description: string; permissions: string[] }) =>
  api<Role>('/admin/roles', j(b))
export const updateRole = (
  id: number,
  b: { name?: string; description?: string; permissions?: string[] },
) => api<Role>(`/admin/roles/${id}`, patch(b))
export const deleteRole = (id: number) => api<void>(`/admin/roles/${id}`, { method: 'DELETE' })

// ── 成员 ────────────────────────────────────────────────────────
export interface UserQuery {
  department_id?: number | null
  status?: UserStatus
  role_id?: number
  search?: string
}

export function listMembers(q: UserQuery = {}): Promise<Member[]> {
  const p = new URLSearchParams()
  if (q.department_id != null) p.set('department_id', String(q.department_id))
  if (q.status) p.set('status', q.status)
  if (q.role_id != null) p.set('role_id', String(q.role_id))
  if (q.search) p.set('search', q.search)
  const qs = p.toString()
  return api<Member[]>(`/admin/users${qs ? `?${qs}` : ''}`)
}

export const memberStats = () => api<Record<string, number>>('/admin/users/stats')

export interface MemberCreate {
  username: string
  display_name: string
  password?: string | null
  role_id: number | null
  department_id: number | null
  employee_no?: string
  email?: string
  phone?: string
  title?: string
}

export const createMember = (b: MemberCreate) =>
  api<TempPasswordResult>('/admin/users', j(b))
export const updateMember = (
  id: number,
  b: Partial<Pick<Member, 'display_name' | 'role_id' | 'department_id' | 'employee_no' | 'email' | 'phone' | 'title'>>,
) => api<Member>(`/admin/users/${id}`, patch(b))
export const setMemberStatus = (id: number, status: Exclude<UserStatus, 'pending'>) =>
  api<Member>(`/admin/users/${id}/status`, j({ status }))
export const resetMemberPassword = (id: number, password?: string | null) =>
  api<TempPasswordResult>(`/admin/users/${id}/reset-password`, j({ password: password ?? null }))
export const approveMember = (id: number, b: { role_id: number | null; department_id: number | null }) =>
  api<Member>(`/admin/users/${id}/approve`, j(b))
export const rejectMember = (id: number) =>
  api<void>(`/admin/users/${id}/reject`, { method: 'POST' })

// ── 团队成员关系(plan/13:团队=带成员与负责人的实体;负责人管本团队)──────────
export interface Membership {
  user_id: number
  team_id: number
  team_role: string
  is_lead: boolean
}

/** 某团队的成员关系(负责人在前)。 */
export const listTeamMembers = (teamId: number) =>
  api<Membership[]>(`/admin/teams/${teamId}/members`)
/** 把成员加入/更新到某团队(组织管理员 或 该团队负责人可调;越权 → 后端 403)。 */
export const addTeamMember = (
  teamId: number,
  b: { user_id: number; team_role?: string; is_lead?: boolean },
) => api<Membership>(`/admin/teams/${teamId}/members`, j(b))
/** 把成员移出某团队。 */
export const removeTeamMember = (teamId: number, userId: number) =>
  api<void>(`/admin/teams/${teamId}/members/${userId}`, { method: 'DELETE' })

// ── 网关上游接入(设置页:配置企业智能体 + 测试连接)──────────────
export type GatewayProtocol = 'openai' | 'rest' | 'native'
export type GatewayAuthType = 'none' | 'bearer' | 'header'

/** GET 返回:密钥已脱敏,只暴露掩码与"是否已设置"。 */
export interface GatewayConfig {
  enabled: boolean
  name: string
  protocol: GatewayProtocol
  endpoint: string
  path: string
  model: string
  auth_type: GatewayAuthType
  auth_header: string
  auth_value_masked: string
  auth_value_set: boolean
  timeout_seconds: number
  verify_tls: boolean
  rest_message_field: string
  rest_response_path: string
}

/** PUT / 测试连接 提交体:auth_value=null 表示不改密钥,""=清空,其它=替换。 */
export interface GatewayConfigWrite {
  enabled: boolean
  name: string
  protocol: GatewayProtocol
  endpoint: string
  path: string
  model: string
  auth_type: GatewayAuthType
  auth_header: string
  auth_value: string | null
  timeout_seconds: number
  verify_tls: boolean
  rest_message_field: string
  rest_response_path: string
}

export interface GatewayProbeResult {
  ok: boolean
  latency_ms: number
  detail: string
  status_code: number | null
}

export const getGatewayConfig = () => api<GatewayConfig>('/admin/gateway-config')
export const saveGatewayConfig = (b: GatewayConfigWrite) =>
  api<GatewayConfig>('/admin/gateway-config', { method: 'PUT', body: JSON.stringify(b) })
export const testGatewayConfig = (b: GatewayConfigWrite) =>
  api<GatewayProbeResult>('/admin/gateway-config/test', j(b))

// ── 控制台实例设置(设置页:真实可写项 + 运行态只读信息)──────────────
export type SettingsEnv = 'prod' | 'staging' | 'demo'

/** 可写偏好(PUT 提交体);全量替换,保存任一子集都需带上其余字段。 */
export interface ConsoleSettingsWrite {
  instance_name: string
  environment: SettingsEnv
}

/** 只读:后端模型出站配置(经 .env 注入,控制台不改,仅如实回显)。 */
export interface BackendModelInfo {
  endpoint: string
  model_name: string
  key_set: boolean
}

/** GET 返回:可写偏好 + 只读后端模型信息。 */
export interface ConsoleSettings extends ConsoleSettingsWrite {
  backend_model: BackendModelInfo
}

export const getConsoleSettings = () => api<ConsoleSettings>('/admin/settings')
export const saveConsoleSettings = (b: ConsoleSettingsWrite) =>
  api<ConsoleSettings>('/admin/settings', { method: 'PUT', body: JSON.stringify(b) })
