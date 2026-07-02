/**
 * 同源 API 客户端基座 —— 全站后端请求的唯一封装。
 *
 * 走相对路径同源请求,会话 Cookie 自动携带;后端按权限点强制鉴权(前端隐藏只是体验)。
 * 非 2xx 抛出后端的 detail 文案(422 校验错误逐条展开),便于直接 toast / 交给 Query 的 error。
 */
import { t } from '@/lib/i18n'

/**
 * 携带 HTTP 状态码的 API 错误。让上层(如 Query 的 retry 判定)按**状态码**决策,
 * 不必去匹配本地化后的错误文案(中文文案匹配在英文 locale 下会失效)。
 */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

// FastAPI 校验错误的 loc 首段是入参位置(body/query/path/...),对用户是噪音,去掉只留字段路径。
const _LOC_PREFIXES = new Set(['body', 'query', 'path', 'header', 'cookie'])

function errorMessage(detail: unknown): string {
  if (typeof detail === 'string') return detail
  if (!Array.isArray(detail)) return t('lib.api.failed')

  const messages = detail
    .map((item) => {
      if (!item || typeof item !== 'object') return ''
      const entry = item as { loc?: unknown; msg?: unknown }
      const segs = Array.isArray(entry.loc) ? [...entry.loc] : []
      if (typeof segs[0] === 'string' && _LOC_PREFIXES.has(segs[0])) segs.shift()
      const loc = segs.join('.')
      const msg = typeof entry.msg === 'string' ? entry.msg : ''
      return [loc, msg].filter(Boolean).join(': ')
    })
    .filter(Boolean)

  return messages.join('; ') || t('lib.api.failed')
}

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
    throw new Error(t('lib.api.offline'))
  }
  if (res.status === 204) return undefined as T
  const text = await res.text()
  let data: unknown
  try {
    data = text ? JSON.parse(text) : undefined
  } catch {
    // 非 JSON 响应体(反代 502 的 HTML 页等)→ 给状态码兜底,而非抛出生硬的 SyntaxError。
    if (res.ok) throw new Error(t('lib.api.bad_response'))
    throw new ApiError(res.status, t('lib.api.server_error', { status: res.status }))
  }
  if (!res.ok) {
    const detail = (data as { detail?: unknown })?.detail
    throw new ApiError(res.status, errorMessage(detail))
  }
  return data as T
}

export const j = (body: unknown): RequestInit => ({ method: 'POST', body: JSON.stringify(body) })
export const patch = (body: unknown): RequestInit => ({
  method: 'PATCH',
  body: JSON.stringify(body),
})
