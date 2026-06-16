import { FlaskConical } from 'lucide-react'
import { defineFeature } from '@/lib/module'
import { EvalPage } from './eval-page'

export const evalModule = defineFeature({
  id: 'eval',
  label: '评测验证',
  icon: FlaskConical,
  group: '取证',
  order: 70,
  requires: 'eval.view',
  component: EvalPage,
})
