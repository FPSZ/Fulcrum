import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api/client'
import type { PolicySet } from './data'

/**
 * 策略中心(接真后端 GET /policies)。返回管线当前装配的声明式 YAML 策略;
 * 后端 DTO 与前端 PolicySet 同构(条件已归一为 {key,value} 串),无需再映射。
 * 策略改动需改 data/policies/*.yml + 重启,刷新放缓(60s)。无报告/无权限 → 回退 seed。
 */
export function usePolicies() {
  return useQuery<PolicySet | null>({
    queryKey: ['policies', 'set'],
    queryFn: () => api<PolicySet | null>('/policies'),
    refetchInterval: 60_000,
  })
}
