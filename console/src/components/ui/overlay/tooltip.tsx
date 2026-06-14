import * as React from 'react'
import * as RT from '@radix-ui/react-tooltip'
import { cn } from '@/lib/utils'

export const TooltipProvider = RT.Provider

export interface TooltipProps {
  content: React.ReactNode
  children: React.ReactNode
  side?: RT.TooltipContentProps['side']
  delay?: number
}

export function Tooltip({ content, children, side = 'top', delay = 250 }: TooltipProps) {
  if (!content) return <>{children}</>
  return (
    <RT.Root delayDuration={delay}>
      <RT.Trigger asChild>{children}</RT.Trigger>
      <RT.Portal>
        <RT.Content
          side={side}
          sideOffset={6}
          className={cn(
            'z-50 select-none rounded-md bg-ink px-2 py-1 text-[11px] font-medium text-white shadow-pop',
            'data-[state=delayed-open]:animate-[pop-in_0.14s_var(--ease-out-quart)]',
          )}
        >
          {content}
          <RT.Arrow className="fill-ink" />
        </RT.Content>
      </RT.Portal>
    </RT.Root>
  )
}
