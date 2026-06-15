import { createContext, useContext, useState, type ReactNode } from 'react'

/**
 * 控制台登录态(占位实现)。
 *
 * 现状:后端 M0 尚无 /auth 接口,这里是**前端占位门禁**——接受任意非空账号+口令,
 * 仅用于把控制台挡在登录后并演示登录过场动画。
 * 接后端时:把 `login` 改为调用 OpenAPI 的鉴权接口、保存会话令牌(走 httpOnly cookie
 * 或内存),并在请求层带上;**密钥/令牌不写死、不入前端源码**(沿用安全红线)。
 */

const KEY = 'fulcrum.auth.v1'

interface AuthValue {
  authed: boolean
  /** 失败时抛错(消息用于表单提示);成功后置 authed=true,触发登录页滑走 */
  login: (account: string, password: string) => Promise<void>
  logout: () => void
}

const Ctx = createContext<AuthValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [authed, setAuthed] = useState(() => localStorage.getItem(KEY) === '1')

  const login = async (account: string, password: string) => {
    if (!account.trim() || !password) throw new Error('请输入账号和口令')
    // 模拟一次网络往返,让按钮的加载态可见
    await new Promise((r) => setTimeout(r, 550))
    localStorage.setItem(KEY, '1')
    setAuthed(true)
  }

  const logout = () => {
    localStorage.removeItem(KEY)
    setAuthed(false)
  }

  return <Ctx.Provider value={{ authed, login, logout }}>{children}</Ctx.Provider>
}

export function useAuth(): AuthValue {
  const c = useContext(Ctx)
  if (!c) throw new Error('useAuth 必须在 AuthProvider 内使用')
  return c
}
