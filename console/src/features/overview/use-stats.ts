import { useQuery } from '@tanstack/react-query'
import { fetchOverviewStats, type OverviewStats } from '@/lib/api/overview'

/**
 * 安全总览实时统计(接真后端)。
 *
 * 每 15s 轮询一次,让 KPI 卡跟随网关真实流量。无权限 / 后端不可达时 query 进入 error,
 * 调用方据此回退到导入备份的演示数据(见 overview-page),不阻断纯前端预览。
 */
export function useOverviewStats() {
  return useQuery<OverviewStats>({
    queryKey: ['overview', 'stats'],
    queryFn: fetchOverviewStats,
    refetchInterval: 15_000,
  })
}
