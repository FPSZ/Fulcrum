import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'

/**
 * 控制台登录态 —— 对接后端服务端会话(HttpOnly Cookie)。
 *
 * 安全模型:会话令牌只存在后端签发的 HttpOnly Cookie 里,前端 JS 读不到、也不保存令牌
 * (无 localStorage)。"登没登上"由 `GET /auth/me` 这一权威来源决定;前端只持有
 * 用户名/显示名这类非敏感信息。口令仅在提交瞬间存在于内存,绝不落地。
 */

export interface SessionUser {
  username: string
  displayName: string
}

interface AuthValue {
  /** 初次会话探测是否完成 —— 完成前不要决定显示登录页还是主控制台,避免闪烁 */
  ready: boolean
  authed: boolean
  user: SessionUser | null
  /** 失败时抛错(消息用于表单提示);成功后置 authed=true,触发登录页滑走 */
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
}

const Ctx = createContext<AuthValue | null>(null)

/** 统一解析后端的当事人响应 */
async function readPrincipal(res: Response): Promise<SessionUser> {
  const data = (await res.json()) as { username: string; display_name: string }
  return { username: data.username, displayName: data.display_name }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [ready, setReady] = useState(false)
  const [user, setUser] = useState<SessionUser | null>(null)

  // 挂载时向后端核实当前会话(Cookie 自动随同源请求携带)
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

  return (
    <Ctx.Provider value={{ ready, authed: user !== null, user, login, logout }}>
      {children}
    </Ctx.Provider>
  )
}

export function useAuth(): AuthValue {
  const c = useContext(Ctx)
  if (!c) throw new Error('useAuth 必须在 AuthProvider 内使用')
  return c
}
