import type * as React from 'react'
import { cn } from '@/lib/utils'

export interface KeyValueProps {
  label: React.ReactNode
  children: React.ReactNode
  className?: string
}

/** 属性键值行(Linear 详情属性区) */
export function KeyValue({ label, children, className }: KeyValueProps) {
  return (
    <div className={cn('flex items-center gap-3 py-[5px] text-[12px]', className)}>
      <span className="w-16 shrink-0 text-ink-3">{label}</span>
      <span className="flex min-w-0 items-center gap-2 text-ink-2">{children}</span>
    </div>
  )
}
