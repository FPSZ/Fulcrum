import { useState } from 'react'
import { FileSearch, Link2, ShieldCheck } from 'lucide-react'
import { Badge, type BadgeTone, Card, EmptyState } from '@/components/ui'
import { useResource } from '@/lib/backup'
import { type MessageKey, useTranslation } from '@/lib/i18n'
import { cn } from '@/lib/utils'
import { type AuditSession, type Disposition, eventLabel } from './data'
import { useAuditSessions } from './use-audit'

const DISP_TONE: Record<Disposition, BadgeTone> = {
  block: 'crit',
  approve: 'high',
  sanitize: 'med',
  allow: 'ok',
}
const DISP_KEY: Record<Disposition, MessageKey> = {
  block: 'audit.disp.block',
  approve: 'audit.disp.approve',
  sanitize: 'audit.disp.sanitize',
  allow: 'audit.disp.allow',
}

export function AuditPage() {
  const { t } = useTranslation()
  // 三态:真后端会话链 → 真;否则用户载入的备份演示数据;都没有 → 诚实空态(绝不自动塞假数据)。
  const live = useAuditSessions().data
  const backup = useResource<AuditSession>('audit')
  const sessions = live && live.length > 0 ? live : backup
  const [selectedId, setSelectedId] = useState('')
  // 选中项不在当前列表(初始 / 真数据替换 seed 后)→ 回退首条
  const session = sessions.find((s) => s.session_id === selectedId) ?? sessions[0] ?? null
  const activeId = session?.session_id ?? ''

  if (sessions.length === 0) {
    return (
      <EmptyState icon={FileSearch} title={t('audit.empty.title')} hint={t('audit.empty.hint')} />
    )
  }

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
                {s.verified ? t('audit.chain_intact') : t('audit.tampered')}
              </Badge>
            </div>
            <p className="mt-1.5 text-[12.5px] leading-snug text-ink-3">{s.scenario}</p>
            <p className="mt-1 text-[12px] text-line-3">
              {t('audit.event_count', { count: s.events.length })}
            </p>
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
                {session.verified ? t('audit.verify_pass') : t('audit.verify_fail')}
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
                          {eventLabel(e.event_type)}
                        </span>
                        {e.decision && (
                          <Badge tone={DISP_TONE[e.decision]}>{t(DISP_KEY[e.decision])}</Badge>
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
          </>
        ) : null}
      </div>
    </div>
  )
}
