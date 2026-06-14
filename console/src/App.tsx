import { useState } from 'react'
import { AppShell } from './components/app/app-shell'
import { Placeholder } from './components/app/placeholder'
import { Toaster, TooltipProvider } from './components/ui'
import { BackupProvider } from './lib/backup'
import { getDefaultFeatureId, getFeature } from './lib/module'

/** 按功能模块注册表渲染当前页面 */
function View({ id }: { id: string }) {
  const feature = getFeature(id)
  if (!feature) return <Placeholder title={id} />
  const Page = feature.component
  return <Page />
}

export function App() {
  const [view, setView] = useState(() => {
    const id = getDefaultFeatureId()
    return getFeature('events') ? 'events' : id
  })
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
