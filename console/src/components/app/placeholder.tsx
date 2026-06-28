import { Hammer, type LucideIcon } from 'lucide-react'
import { EmptyState } from '@/components/ui'
import { useTranslation } from '@/lib/i18n'

export function Placeholder({ title, icon = Hammer }: { title: string; icon?: LucideIcon }) {
  const { t } = useTranslation()
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <EmptyState
        icon={icon}
        title={t('app.placeholder.title', { title })}
        hint={t('app.placeholder.hint')}
      />
    </div>
  )
}
