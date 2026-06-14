import * as React from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const badge = cva(
  'inline-flex items-center gap-1.5 rounded-xs px-2 py-0.5 text-[11px] font-medium whitespace-nowrap',
  {
    variants: {
      tone: {
        neutral: 'bg-surface-2 text-ink-2',
        crit: 'bg-crit/12 text-crit',
        high: 'bg-high/15 text-high',
        med: 'bg-med/18 text-med',
        ok: 'bg-ok/14 text-ok',
        info: 'bg-info/12 text-info',
        accent: 'bg-accent/10 text-accent-ink',
      },
    },
    defaultVariants: { tone: 'neutral' },
  },
)

export type BadgeTone = NonNullable<VariantProps<typeof badge>['tone']>

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badge> {
  dot?: boolean
}

export function Badge({ tone, dot, className, children, ...props }: BadgeProps) {
  return (
    <span className={cn(badge({ tone }), className)} {...props}>
      {dot && <span className="h-1.5 w-1.5 rounded-full bg-current opacity-90" />}
      {children}
    </span>
  )
}
