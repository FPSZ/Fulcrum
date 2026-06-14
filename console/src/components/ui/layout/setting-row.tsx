import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

/** 一节设置:标题 + 描述 + 卡片内若干 SettingRow */
export function SettingSection({
  title,
  desc,
  children,
  className,
}: {
  title: ReactNode
  desc?: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <section className={cn('mb-7', className)}>
      <h2 className="text-[14px] font-semibold tracking-[-0.01em]">{title}</h2>
      {desc && <p className="mt-1 text-[12px] leading-relaxed text-ink-3">{desc}</p>}
      <div className="mt-3 divide-y divide-line rounded-lg bg-surface px-4 shadow-card">{children}</div>
    </section>
  )
}

/** 单行设置:左侧 标签 + 说明,右侧 控件 */
export function SettingRow({
  label,
  hint,
  children,
  className,
}: {
  label: ReactNode
  hint?: ReactNode
  children?: ReactNode
  className?: string
}) {
  return (
    <div className={cn('flex items-start justify-between gap-6 py-3.5', className)}>
      <div className="min-w-0">
        <div className="text-[13px] font-medium text-ink">{label}</div>
        {hint && <div className="mt-0.5 text-[12px] leading-relaxed text-ink-3">{hint}</div>}
      </div>
      <div className="flex shrink-0 items-center gap-2 pt-0.5">{children}</div>
    </div>
  )
}
