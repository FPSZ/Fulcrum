import { Tooltip } from '@/components/ui'
import { cn } from '@/lib/utils'
import { LEVEL_BAR, LEVEL_LABEL, SOURCE_ICON, TRUST_TONE } from './meta'
import type { RiskLevel, SecurityEvent } from './types'

const TRUST_TEXT: Record<string, string> = {
  crit: 'text-crit',
  high: 'text-high',
  ok: 'text-ok',
}

export function EventRow({
  event: e,
  count = 1,
  level,
  selected,
  last,
  onSelect,
}: {
  event: SecurityEvent
  /** 折叠条数:>1 时该行代表同一会话同标题的多条判定,行尾标 ×N */
  count?: number
  /** 折叠桶内最坏等级(决定左侧色条);缺省回退代表事件自身等级 */
  level?: RiskLevel
  selected: boolean
  last?: boolean
  onSelect: () => void
}) {
  const SrcIcon = SOURCE_ICON[e.srcType]
  const lvl = level ?? e.level
  return (
    <button
      type="button"
      onClick={onSelect}
      data-selected={selected || undefined}
      className={cn(
        'focus-ring group relative flex h-[40px] w-full items-center gap-3.5 pl-[18px] pr-4 text-left',
        'transition-colors duration-100 hover:bg-surface-2/70',
        !last && 'border-b border-line/55',
        'data-[selected]:bg-accent/10 data-[selected]:hover:bg-accent/10',
      )}
    >
      {/* 最左竖色条 = 严重等级(纯颜色,不写字;折叠时取桶内最坏等级) */}
      <Tooltip content={`${LEVEL_LABEL[lvl]}风险`} side="right">
        <span className={cn('absolute inset-y-0 left-0 w-1', LEVEL_BAR[lvl])} />
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

      {count > 1 && (
        <Tooltip content={`本会话该类判定共 ${count} 条,已折叠为一行`}>
          <span className="font-data shrink-0 rounded-full bg-surface-2 px-1.5 py-0.5 text-[11.5px] font-medium tabular-nums text-ink-mute">
            ×{count}
          </span>
        </Tooltip>
      )}

      <Tooltip content={`来源:${e.srcType} · ${e.trust}`}>
        <span className="flex shrink-0 items-center gap-1.5 text-[14px] text-ink-3">
          <SrcIcon className={cn('h-3.5 w-3.5', TRUST_TEXT[TRUST_TONE[e.trust]])} strokeWidth={1.8} />
          <span className="hidden sm:inline">{e.srcType}</span>
        </span>
      </Tooltip>
    </button>
  )
}
