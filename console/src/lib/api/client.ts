/**
 * 同源 API 客户端基座 —— 全站后端请求的唯一封装。
 *
 * 走相对路径同源请求,会话 Cookie 自动携带;后端按权限点强制鉴权(前端隐藏只是体验)。
 * 非 2xx 抛出后端的 detail 文案,便于直接 toast / 交给 TanStack Query 的 error。
 */

/** 统一请求封装:非 2xx 抛出后端的 detail 文案。 */
export async function api<T>(path: string, init?: RequestInit): Promise<T> {
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
    const detail = (data as { detail?: unknown })?.detail
    throw new Error(typeof detail === 'string' ? detail : '操作失败')
  }
  return data as T
}

export const j = (body: unknown): RequestInit => ({ method: 'POST', body: JSON.stringify(body) })
export const patch = (body: unknown): RequestInit => ({
  method: 'PATCH',
  body: JSON.stringify(body),
})
