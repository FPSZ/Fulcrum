import { FileSearch } from 'lucide-react'
import { defineFeature } from '@/lib/module'
import { AuditPage } from './audit-page'

export const auditModule = defineFeature({
  id: 'audit',
  label: '审计溯源',
  icon: FileSearch,
  group: '取证',
  order: 60,
  requires: 'audit.view',
  component: AuditPage,
})
