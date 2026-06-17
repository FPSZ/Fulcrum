/** 会话事件流 API —— 对接后端 GET /events(审计判定点投影成事件行)。 */

import { api } from './client'

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
