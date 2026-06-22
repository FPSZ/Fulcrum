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
  dev: true, // 测试集 ASR/FPR 记分卡,纯开发/答辩用;政企管理员用不到,默认隐藏
  component: EvalPage,
})
