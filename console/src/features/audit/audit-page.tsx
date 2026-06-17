import { useState } from 'react'
import { Link2, ShieldCheck } from 'lucide-react'
import { Badge, type BadgeTone, Card } from '@/components/ui'
import { cn } from '@/lib/utils'
import { AUDIT_SESSIONS, type Disposition, EVENT_LABEL } from './data'
import { useAuditSessions } from './use-audit'

const DISP_TONE: Record<Disposition, BadgeTone> = {
  block: 'crit',
  approve: 'high',
  sanitize: 'med',
  allow: 'ok',
}
const DISP_LABEL: Record<Disposition, string> = {
  block: '阻断',
  approve: '审批',
  sanitize: '净化',
  allow: '放行',
}

export function AuditPage() {
  // 接真后端:有真实会话链则用真;无权限/不可达/空 → 回退演示 seed(纯前端预览不受影响)。
  const live = useAuditSessions().data
  const sessions = live && live.length > 0 ? live : AUDIT_SESSIONS
  const [selectedId, setSelectedId] = useState('')
  // 选中项不在当前列表(初始 / 真数据替换 seed 后)→ 回退首条
  const session = sessions.find((s) => s.session_id === selectedId) ?? sessions[0] ?? null
  const activeId = session?.session_id ?? ''

  return (
    <div className="flex min-h-0 flex-1">
      {/* 会话列表 */}
      <div className="w-[320px] shrink-0 space-y-2 overflow-y-auto border-r border-line p-3 max-[900px]:w-[260px]">
        {sessions.map((s) => (
          <button
            key={s.session_id}
            type="button"
            onClick={() => setSelectedId(s.session_id)}
            className={cn(
              'focus-ring block w-full rounded-md border p-3 text-left transition-colors',
              s.session_id === activeId
                ? 'border-accent/40 bg-accent/5'
                : 'border-line bg-surface hover:border-line-3',
            )}
          >
            <div className="flex items-center gap-2">
              <code className="text-[13px] font-medium text-ink">{s.session_id}</code>
              <Badge tone={s.verified ? 'ok' : 'crit'} dot className="ml-auto">
                {s.verified ? '链完整' : '已篡改'}
              </Badge>
            </div>
            <p className="mt-1.5 text-[12.5px] leading-snug text-ink-3">{s.scenario}</p>
            <p className="mt-1 text-[12px] text-line-3">{s.events.length} 个事件</p>
          </button>
        ))}
      </div>

      {/* 事件链 */}
      <div className="min-h-0 flex-1 overflow-y-auto p-4">
        {session ? (
          <>
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
              <h2 className="text-[15px] font-semibold text-ink">{session.session_id}</h2>
              <Badge tone={session.verified ? 'ok' : 'crit'}>
                <ShieldCheck className="h-3.5 w-3.5" />
                {session.verified ? 'Hash-chain 校验通过' : '校验失败,疑似篡改'}
              </Badge>
            </div>
            <p className="mt-1 text-[13px] text-ink-3">{session.scenario}</p>

            <Card className="mt-3 p-4">
              <ol className="space-y-0">
                {session.events.map((e, i) => (
                  <li key={e.index} className="flex gap-3">
                    {/* 时间轴竖线 + 节点 */}
                    <div className="flex flex-col items-center">
                      <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-surface-2 text-[12px] tabular-nums text-ink-3">
                        {e.index}
                      </span>
                      {i < session.events.length - 1 && <span className="my-0.5 w-px flex-1 bg-line" />}
                    </div>
                    <div className="min-w-0 flex-1 pb-4">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-[14px] font-medium text-ink">
                          {EVENT_LABEL[e.event_type] ?? e.event_type}
                        </span>
                        {e.decision && (
                          <Badge tone={DISP_TONE[e.decision]}>{DISP_LABEL[e.decision]}</Badge>
                        )}
                        {e.subject_id && (
                          <code className="text-[12.5px] text-ink-3">{e.subject_id}</code>
                        )}
                      </div>
                      {e.reason && <p className="mt-1 text-[13px] text-ink-2">{e.reason}</p>}
                      <div className="mt-1 flex items-center gap-1.5 font-mono text-[11.5px] text-line-3">
                        <Link2 className="h-3 w-3" />
                        {e.prev_hash} → <span className="text-ink-3">{e.event_hash}</span>
                      </div>
                    </div>
                  </li>
                ))}
              </ol>
            </Card>
            <p className="mt-3 text-[12.5px] text-ink-3">
              每个事件 `event_hash = sha256(prev_hash + 事件内容)`,环环相扣;任一被篡改则后续校验失败。
              数据来自 <code className="text-ink-2">/audit/&#123;session_id&#125;</code>(append-only 防篡改链)。
            </p>
          </>
        ) : null}
      </div>
    </div>
  )
}
