import type { LucideIcon } from 'lucide-react'

export interface EmptyStateProps {
  icon: LucideIcon
  title: string
  hint?: string
}

export function EmptyState({ icon: Icon, title, hint }: EmptyStateProps) {
  return (
    <div className="grid flex-1 place-items-center p-10 text-center">
      <div>
        <Icon className="mx-auto mb-3 h-7 w-7 text-line-3" strokeWidth={1.4} />
        <p className="text-[15px] text-ink-3">{title}</p>
        {hint && <p className="mt-1 text-[14px] text-ink-mute">{hint}</p>}
      </div>
    </div>
  )
}
