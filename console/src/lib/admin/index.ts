/**
 * 管理后台 API 客户端(组织 / 角色 / 成员 / 权限)。
 * 全部走相对路径同源请求,会话 Cookie 自动携带;后端按权限点强制鉴权(前端隐藏只是体验)。
 */

export interface PermissionDef {
  key: string
  label: string
  group: string
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

/** 统一请求封装:非 2xx 抛出后端的 detail 文案,便于直接 toast。 */
async function api<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response
  try {
    res = await fetch(path, {
      credentials: 'include',
      headers: init?.body ? { 'Content-Type': 'application/json' } : undefined,
      ...init,
    })
  } catch {
    throw new Error('无法连接服务,请稍后再试')
  }
  if (res.status === 204) return undefined as T
  const text = await res.text()
  const data = text ? JSON.parse(text) : undefined
  if (!res.ok) {
    const detail = data?.detail
    throw new Error(typeof detail === 'string' ? detail : '操作失败')
  }
  return data as T
}

const j = (body: unknown): RequestInit => ({ method: 'POST', body: JSON.stringify(body) })
const patch = (body: unknown): RequestInit => ({ method: 'PATCH', body: JSON.stringify(body) })

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
