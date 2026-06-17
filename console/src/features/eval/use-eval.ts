import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api/client'
import type { EvalReport } from './data'

/**
 * 评测报告(接真后端 GET /eval/report)。评测是离线产物,刷新放缓(30s)。
 * 后端无报告时返回 null;无权限/不可达 → query error。两种情况调用方都回退演示 seed。
 */
export function useEvalReport() {
  return useQuery<EvalReport | null>({
    queryKey: ['eval', 'report'],
    queryFn: () => api<EvalReport | null>('/eval/report'),
    refetchInterval: 30_000,
  })
}
