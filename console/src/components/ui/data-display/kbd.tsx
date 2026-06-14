import type * as React from 'react'
import { cn } from '@/lib/utils'

export function Kbd({ className, children }: React.PropsWithChildren<{ className?: string }>) {
  return (
    <kbd
      className={cn(
        'font-data rounded border border-line-2 px-1 py-px text-[10px] leading-none text-ink-mute',
        className,
      )}
    >
      {children}
    </kbd>
  )
}
