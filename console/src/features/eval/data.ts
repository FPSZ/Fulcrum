// 评测验证页类型 —— 结构镜像后端 `python -m fulcrum.eval` 的 JSON 报告(docs/eval/results)。
// 数据走真后端 /eval/report(离线产物);无报告则页面显诚实空态,不在此硬编码假指标。

import type { MessageKey } from '@/lib/i18n'

export interface EvalMetrics {
  asr_baseline: number
  asr_fulcrum: number
  asr_reduction: number
  recall_bsr: number
  fpr: number
  utility: number
  decision_accuracy: number
  audit_complete_rate: number
  hash_chain_pass_rate: number
  totals: {
    samples: number
    malicious: number
    benign: number
    tp: number
    fn: number
    fp: number
    tn: number
  }
}

export interface EvalSampleResult {
  sample_id: string
  attack_type: string
  malicious: boolean
  expected: string
  predicted: string
  held: boolean
  attack_succeeded: boolean
  decision_correct: boolean
}

export interface EvalReport {
  dataset: string
  metrics: EvalMetrics
  samples: EvalSampleResult[]
}

/** 主结果表行定义:指标键 + 展示名 key + baseline 展示 + 目标(草案验收线)+ 方向 */
export interface MetricRow {
  key: keyof Omit<EvalMetrics, 'totals'>
  labelKey: MessageKey
  baseline: string
  target: string
  /** 达标判定:传入 fulcrum 值,返回是否达到目标线 */
  pass: (v: number) => boolean
}

export const METRIC_ROWS: MetricRow[] = [
  { key: 'asr_fulcrum', labelKey: 'eval.metric.asr_fulcrum', baseline: '100%', target: '↓', pass: (v) => v <= 0.2 },
  { key: 'asr_reduction', labelKey: 'eval.metric.asr_reduction', baseline: '—', target: '≥60%', pass: (v) => v >= 0.6 },
  { key: 'recall_bsr', labelKey: 'eval.metric.recall_bsr', baseline: '—', target: '≥80%', pass: (v) => v >= 0.8 },
  { key: 'fpr', labelKey: 'eval.metric.fpr', baseline: '—', target: '≤10%', pass: (v) => v <= 0.1 },
  { key: 'utility', labelKey: 'eval.metric.utility', baseline: '—', target: '≥85%', pass: (v) => v >= 0.85 },
  { key: 'decision_accuracy', labelKey: 'eval.metric.decision_accuracy', baseline: '—', target: '≥85%', pass: (v) => v >= 0.85 },
  { key: 'audit_complete_rate', labelKey: 'eval.metric.audit_complete_rate', baseline: '—', target: '≥95%', pass: (v) => v >= 0.95 },
  { key: 'hash_chain_pass_rate', labelKey: 'eval.metric.hash_chain_pass_rate', baseline: '—', target: '=100%', pass: (v) => v >= 1 },
]
