import { Hammer, type LucideIcon } from 'lucide-react'
import { EmptyState } from '@/components/ui'

export function Placeholder({ title, icon = Hammer }: { title: string; icon?: LucideIcon }) {
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <EmptyState icon={icon} title={`${title} · 建设中`} hint="该模块将在后续版本接入" />
    </div>
  )
}
