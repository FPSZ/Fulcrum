import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'

/**
 * 控制台登录态 —— 对接后端服务端会话(HttpOnly Cookie)+ RBAC 权限点。
 *
 * 安全模型:会话令牌只存在后端签发的 HttpOnly Cookie 里,前端 JS 读不到、也不保存令牌
 * (无 localStorage)。"登没登上 / 有哪些权限"由 `GET /auth/me` 这一权威来源决定;
 * 前端只持有用户名/显示名/角色/权限点这类非敏感信息。口令仅在提交瞬间存在于内存。
 *
 * 注意:前端按权限隐藏菜单只是体验优化,**真正的访问控制在后端**(每个接口 require_permission)。
 */

export interface SessionUser {
  username: string
  displayName: string
  roleKey: string | null
  roleName: string | null
  permissions: string[]
  /** 所属团队 id */
  teamIds: number[]
  /** 作为负责人可管的团队 id(已展开子树);非空 = 我是团队负责人 */
  managedTeams: number[]
}

interface AuthValue {
  /** 初次会话探测是否完成 —— 完成前不要决定显示登录页还是主控制台,避免闪烁 */
  ready: boolean
  authed: boolean
  user: SessionUser | null
  /** 是否拥有某权限点 */
  has: (permission: string) => boolean
  /** 我是不是某团队的负责人(managed_teams 非空)—— 据此放出本团队管理界面 */
  isLead: boolean
  /** 我能否管理某团队(组织级 users.manage 或该团队负责人) */
  canManageTeam: (teamId: number) => boolean
  /** 失败时抛错(消息用于表单提示);成功后置 authed=true,触发登录页滑走 */
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
}

const Ctx = createContext<AuthValue | null>(null)

async function readPrincipal(res: Response): Promise<SessionUser> {
  const d = (await res.json()) as {
    username: string
    display_name: string
    role_key: string | null
    role_name: string | null
    permissions: string[]
    team_ids?: number[]
    managed_teams?: number[]
  }
  return {
    username: d.username,
    displayName: d.display_name,
    roleKey: d.role_key,
    roleName: d.role_name,
    permissions: d.permissions ?? [],
    teamIds: d.team_ids ?? [],
    managedTeams: d.managed_teams ?? [],
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [ready, setReady] = useState(false)
  const [user, setUser] = useState<SessionUser | null>(null)

  useEffect(() => {
    let alive = true
    fetch('/auth/me', { credentials: 'include' })
      .then(async (res) => (res.ok ? await readPrincipal(res) : null))
      .catch(() => null)
      .then((u) => {
        if (alive) {
          setUser(u)
          setReady(true)
        }
      })
    return () => {
      alive = false
    }
  }, [])

  const login = async (username: string, password: string) => {
    if (!username.trim() || !password) throw new Error('请输入账号和口令')
    let res: Response
    try {
      res = await fetch('/auth/login', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username.trim(), password }),
      })
    } catch {
      throw new Error('无法连接服务,请稍后再试')
    }
    if (res.ok) {
      setUser(await readPrincipal(res))
      return
    }
    if (res.status === 429) throw new Error('尝试过于频繁,账号已被临时锁定,请稍后再试')
    if (res.status === 403) {
      const d = await res.json().catch(() => null)
      throw new Error(typeof d?.detail === 'string' ? d.detail : '账号不可用')
    }
    if (res.status === 401) throw new Error('账号或口令错误')
    throw new Error('登录失败,请稍后再试')
  }

  const logout = async () => {
    try {
      await fetch('/auth/logout', { method: 'POST', credentials: 'include' })
    } finally {
      setUser(null)
    }
  }

  const perms = useMemo(() => new Set(user?.permissions ?? []), [user])
  const managed = useMemo(() => new Set(user?.managedTeams ?? []), [user])
  const has = (p: string) => perms.has(p)
  const value: AuthValue = {
    ready,
    authed: user !== null,
    user,
    has,
    isLead: managed.size > 0,
    canManageTeam: (teamId) => perms.has('users.manage') || managed.has(teamId),
    login,
    logout,
  }
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useAuth(): AuthValue {
  const c = useContext(Ctx)
  if (!c) throw new Error('useAuth 必须在 AuthProvider 内使用')
  return c
}

/**
 * 申请账号(公开):提交后落为"待审批",需管理员批准方可登录。
 * 不建立会话、不返回令牌 —— 只是把申请投递给后端。
 */
export async function requestAccount(
  username: string,
  password: string,
  displayName: string,
): Promise<void> {
  let res: Response
  try {
    res = await fetch('/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: username.trim(),
        password,
        display_name: displayName.trim(),
      }),
    })
  } catch {
    throw new Error('无法连接服务,请稍后再试')
  }
  if (res.ok) return
  const d = await res.json().catch(() => null)
  throw new Error(typeof d?.detail === 'string' ? d.detail : '申请失败,请稍后再试')
}
