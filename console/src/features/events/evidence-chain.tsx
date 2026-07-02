import type { ReactNode } from 'react'
import { AlertTriangle, Check } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/lib/i18n'
import { TRUST_LABEL } from './meta'
import type { SecurityEvent } from './types'

type StageTone = 'accent' | 'warn' | 'ok' | 'block'

function Stage({
  tone = 'accent',
  label,
  last,
  children,
}: {
  tone?: StageTone
  label: string
  last?: boolean
  children: ReactNode
}) {
  const node =
    tone === 'block'
      ? 'border-crit'
      : tone === 'ok'
        ? 'border-ok'
        : tone === 'warn'
          ? 'border-high'
          : 'border-accent'
  return (
    <div className="relative py-[11px] pl-[26px]">
      {!last && <span className="absolute left-[5px] top-[22px] -bottom-px w-[1.5px] bg-line-2" />}
      <span
        className={cn(
          'absolute left-0 top-[14px] z-10 h-[11px] w-[11px] rounded-full border-2 bg-surface',
          node,
        )}
      />
      <div className="text-[12px] font-semibold uppercase tracking-[0.06em] text-ink-mute">
        {label}
      </div>
      <div className="mt-1.5">{children}</div>
    </div>
  )
}

/** 证据归因链(签名元素):来源→意图→参数→证据化归因→策略→处置→hash-chain */
export function EvidenceChain({ event: e }: { event: SecurityEvent }) {
  const { t } = useTranslation()
  const dispTone: StageTone = e.disp === 'block' ? 'block' : e.disp === 'allow' ? 'ok' : 'warn'
  return (
    <div className="relative px-[18px] pb-4 pt-1">
      <Stage tone="warn" label={`${t('events.chain.source')} · ${TRUST_LABEL[e.trust]}`}>
        <div className="rounded-r-sm border-l-2 border-high bg-inset px-[11px] py-[9px] text-[14px] leading-relaxed text-ink-2">
          {e.excerpt}
        </div>
      </Stage>

      <Stage label={t('events.chain.intent')}>
        {e.intent?.trim() ? (
          <p className="text-[15px] leading-relaxed text-ink">{e.intent}</p>
        ) : (
          <p className="text-[14px] text-ink-mute">{t('events.chain.none')}</p>
        )}
      </Stage>

      <Stage label={t('events.chain.args')}>
        {e.args?.trim() ? (
          <pre className="font-data overflow-x-auto whitespace-pre-wrap break-all rounded-sm bg-inset px-[11px] py-[9px] text-[14px] leading-relaxed text-ink-2">
            {e.args}
          </pre>
        ) : (
          <p className="text-[14px] text-ink-mute">{t('events.chain.none')}</p>
        )}
      </Stage>

      <Stage tone="warn" label={t('events.chain.derived')}>
        {e.derived?.trim() ? (
          <>
            <div className="h-1.5 overflow-hidden rounded bg-surface-2">
              <div
                className="h-full rounded bg-high"
                style={{ width: `${Math.round(e.conf * 100)}%` }}
              />
            </div>
            <div className="mt-1.5 flex justify-between text-[13px] text-ink-3">
              <span>{e.derived}</span>
              <span className="font-data">{t('events.chain.conf', { conf: e.conf.toFixed(2) })}</span>
            </div>
          </>
        ) : (
          <p className="text-[14px] text-ink-mute">{t('events.chain.none')}</p>
        )}
      </Stage>

      <Stage label={t('events.chain.policy')}>
        <span className="font-data rounded-xs bg-inset px-[7px] py-0.5 text-[13px] text-ink-2">
          {e.policy}
        </span>
      </Stage>

      <Stage tone={dispTone} label={`${t('events.chain.disposition')} · ${e.risk}`}>
        <p className="text-[15px] leading-relaxed text-ink">{e.reason}</p>
      </Stage>

      <Stage tone={e.verified ? 'accent' : 'block'} label={t('events.chain.hashchain')} last>
        {e.verified ? (
          <span className="inline-flex items-center gap-1.5 text-[13px] font-medium text-ok">
            <Check className="h-[13px] w-[13px]" /> {t('events.chain.verified')}
          </span>
        ) : (
          <div className="flex items-start gap-2.5 rounded-sm bg-crit/12 px-3 py-2.5 text-crit">
            <AlertTriangle className="mt-px h-4 w-4 shrink-0" />
            <div>
              <b className="text-[14px] font-semibold">{t('events.chain.tamper_title')}</b>
              <p className="mt-0.5 text-[13px] opacity-85">
                {t('events.chain.tamper_desc')}
              </p>
            </div>
          </div>
        )}
      </Stage>
    </div>
  )
}
