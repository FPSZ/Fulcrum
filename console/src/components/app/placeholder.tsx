import { Hammer, type LucideIcon } from 'lucide-react'
import { EmptyState } from '@/components/ui'

export function Placeholder({ title, icon = Hammer }: { title: string; icon?: LucideIcon }) {
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <header className="flex h-12 shrink-0 items-center border-b border-line px-4">
        <h1 className="text-sm font-semibold tracking-[-0.014em]">{title}</h1>
      </header>
      <EmptyState icon={icon} title={`${title} · 建设中`} hint="该模块将在后续版本接入" />
    </div>
  )
}
