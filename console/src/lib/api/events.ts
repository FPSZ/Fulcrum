/** 会话事件流 API —— 对接后端 GET /events(审计判定点投影成事件行)。 */

import { api, j } from './client'

/** 后端 SecurityEventDTO 的镜像:枚举为后端原值,时间为 epoch 秒,前端再做薄映射。 */
export interface SecurityEventDTO {
  id: string
  time: number
  sess: string
  src_type: string
  trust: string
  risk: string
  tool: string
  policy: string
  level: string
  disp: string
  verified: boolean
  excerpt: string
  intent: string
  args: string
  conf: number
  derived: string
  reason: string
}

export const fetchEvents = (limit = 200) =>
  api<SecurityEventDTO[]>(`/events?limit=${limit}`)

/** 处置一条待审批事件:批准放行 / 维持阻断(需 events.handle;越权 → 后端 403)。 */
export const resolveEvent = (id: string, decision: 'allow' | 'block', note = '') =>
  api<{ ok: boolean }>(`/events/${encodeURIComponent(id)}/resolve`, j({ decision, note }))
