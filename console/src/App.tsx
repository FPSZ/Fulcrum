import { useState } from 'react'
import { AppShell } from './components/app/app-shell'
import { Placeholder } from './components/app/placeholder'
import { Toaster, TooltipProvider } from './components/ui'
import { BackupProvider } from './lib/backup'
import { EventsPage } from './features/events/events-page'
import { SettingsPage } from './features/settings/settings-page'

const NAV_LABELS: Record<string, string> = {
  overview: '总览',
  policies: '策略中心',
  tools: '工具网关',
  supply: '供应链',
  audit: '审计溯源',
  eval: '评测验证',
}

function View({ id }: { id: string }) {
  if (id === 'events') return <EventsPage />
  if (id === 'settings') return <SettingsPage />
  return <Placeholder title={NAV_LABELS[id] ?? id} />
}

export function App() {
  const [view, setView] = useState('events')
  return (
    <BackupProvider>
      <TooltipProvider delayDuration={250}>
        <AppShell active={view} onNavigate={setView}>
          <View id={view} />
        </AppShell>
        <Toaster />
      </TooltipProvider>
    </BackupProvider>
  )
}
