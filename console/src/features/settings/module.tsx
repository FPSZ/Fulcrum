import { Settings } from 'lucide-react'
import { defineFeature } from '@/lib/module'
import { lazy } from 'react'

export const settingsModule = defineFeature({
  id: 'settings',
  label: '系统设置',
  icon: Settings,
  group: '系统',
  order: 90,
  requires: 'settings.view',
  component: lazy(() => import('./settings-page').then((m) => ({ default: m.SettingsPage }))),
})
