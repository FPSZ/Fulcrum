import { cn } from '@/lib/utils'

export type DotTone = 'crit' | 'high' | 'med' | 'ok' | 'info' | 'accent' | 'mute'

const tones: Record<DotTone, string> = {
  crit: 'bg-crit',
  high: 'bg-high',
  med: 'bg-med',
  ok: 'bg-ok',
  info: 'bg-info',
  accent: 'bg-accent',
  mute: 'bg-ink-mute',
}

export interface StatusDotProps {
  tone?: DotTone
  shape?: 'dot' | 'square'
  className?: string
}

export function StatusDot({ tone = 'mute', shape = 'dot', className }: StatusDotProps) {
  return (
    <span
      className={cn(
        'inline-block shrink-0',
        shape === 'square' ? 'h-1.5 w-1.5 rounded-[2px]' : 'h-2 w-2 rounded-full',
        tones[tone],
        className,
      )}
    />
  )
}
