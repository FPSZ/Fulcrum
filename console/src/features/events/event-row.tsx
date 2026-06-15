import { Tooltip } from '@/components/ui'
import { cn } from '@/lib/utils'
import { LEVEL_BAR, LEVEL_LABEL, SOURCE_ICON, TRUST_TONE } from './meta'
import type { SecurityEvent } from './types'

const TRUST_TEXT: Record<string, string> = {
  crit: 'text-crit',
  high: 'text-high',
  ok: 'text-ok',
}

export function EventRow({
  event: e,
  selected,
  onSelect,
}: {
  event: SecurityEvent
  selected: boolean
  onSelect: () => void
}) {
  const SrcIcon = SOURCE_ICON[e.srcType]
  return (
    <button
      type="button"
      onClick={onSelect}
      data-selected={selected || undefined}
      className={cn(
        'focus-ring group relative flex h-[42px] w-full items-center gap-3.5 border-b border-line pl-[18px] pr-4 text-left',
        'bg-white/48 transition-colors duration-100 hover:bg-white/70',
        'data-[selected]:bg-accent/12 data-[selected]:hover:bg-accent/12',
      )}
    >
      {/* 最左竖色条 = 严重等级(纯颜色,不写字) */}
      <Tooltip content={`${LEVEL_LABEL[e.level]}风险`} side="right">
        <span className={cn('absolute inset-y-0 left-0 w-1', LEVEL_BAR[e.level])} />
      </Tooltip>

      <span
        className={cn(
          'font-data w-[62px] shrink-0 text-[13px]',
          e.verified ? 'text-ink-3' : 'text-crit',
        )}
      >
        {e.time}
      </span>

      <span className="min-w-0 flex-1 truncate text-[15px] text-ink">{e.risk}</span>

      <Tooltip content={`来源:${e.srcType} · ${e.trust}`}>
        <span className="flex shrink-0 items-center gap-1.5 text-[14px] text-ink-3">
          <SrcIcon className={cn('h-3.5 w-3.5', TRUST_TEXT[TRUST_TONE[e.trust]])} strokeWidth={1.8} />
          <span className="hidden sm:inline">{e.srcType}</span>
        </span>
      </Tooltip>
    </button>
  )
}
