import * as RTG from '@radix-ui/react-toggle-group'
import type * as React from 'react'
import { cn } from '@/lib/utils'

export interface SegmentedItem {
  value: string
  label: React.ReactNode
  count?: number
}

export interface SegmentedProps {
  value: string
  onValueChange: (value: string) => void
  items: SegmentedItem[]
  className?: string
}

/** Linear 式分段控件 */
export function Segmented({ value, onValueChange, items, className }: SegmentedProps) {
  return (
    <RTG.Root
      type="single"
      value={value}
      onValueChange={(v) => v && onValueChange(v)}
      className={cn('inline-flex shrink-0 gap-0.5 rounded-sm border border-line bg-subtle p-0.5', className)}
    >
      {items.map((it) => (
        <RTG.Item
          key={it.value}
          value={it.value}
          className={cn(
            'focus-ring shrink-0 whitespace-nowrap rounded-[4px] px-2.5 py-1 text-[14px] font-medium text-ink-3 transition-colors duration-150',
            'hover:text-ink data-[state=on]:bg-surface data-[state=on]:text-ink data-[state=on]:shadow-xs',
          )}
        >
          {it.label}
          {typeof it.count === 'number' && (
            <span className="ml-1.5 font-data text-[13px] opacity-60">{it.count}</span>
          )}
        </RTG.Item>
      ))}
    </RTG.Root>
  )
}
