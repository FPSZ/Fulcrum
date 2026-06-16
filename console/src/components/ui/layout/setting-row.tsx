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
      <h2 className="text-[16px] font-semibold tracking-[-0.01em]">{title}</h2>
      {desc && <p className="mt-1 text-[14px] leading-relaxed text-ink-3">{desc}</p>}
      <div className="glass-card mt-3 divide-y divide-line/70 rounded-lg px-4">{children}</div>
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
    <div
      className={cn(
        // 移动端:标签在上、控件占满整行;桌面端:左标签右控件
        'flex flex-col gap-2 py-3.5 sm:flex-row sm:items-start sm:justify-between sm:gap-6',
        className,
      )}
    >
      <div className="min-w-0">
        <div className="text-[15px] font-medium text-ink">{label}</div>
        {hint && <div className="mt-0.5 text-[14px] leading-relaxed text-ink-3">{hint}</div>}
      </div>
      <div className="flex max-w-full shrink-0 items-center gap-2 sm:pt-0.5 [&_input]:max-w-full">
        {children}
      </div>
    </div>
  )
}
