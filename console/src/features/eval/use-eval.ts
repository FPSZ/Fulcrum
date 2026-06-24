import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api/client'
import type { EvalReport } from './data'

const KEY = ['eval', 'report']

/**
 * 评测报告(接真后端 GET /eval/report)。评测是产物,刷新放缓(30s)。
 * 后端无报告时返回 null;无权限/不可达 → query error。两种情况调用方都回退演示 seed。
 */
export function useEvalReport() {
  return useQuery<EvalReport | null>({
    queryKey: KEY,
    queryFn: () => api<EvalReport | null>('/eval/report'),
    refetchInterval: 30_000,
  })
}

/**
 * 发起评测(POST /eval/run,需 eval.run)。后端回放样例集(~0.1s)写产物并直接返回新报告,
 * 用返回值回填缓存,无需等轮询。进行中再次发起 → 后端 409。
 */
export function useRunEval() {
  const qc = useQueryClient()
  return useMutation<EvalReport | null, Error, void>({
    mutationFn: () => api<EvalReport | null>('/eval/run', { method: 'POST' }),
    onSuccess: (report) => qc.setQueryData(KEY, report),
  })
}
