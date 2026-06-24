import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api/client'
import type { PolicySet, PolicySetWrite } from './data'

const KEY = ['policies', 'set']

/**
 * 策略中心(接真后端 GET /policies)。返回管线当前装配的声明式 YAML 策略;
 * 后端 DTO 与前端 PolicySet 同构(条件已归一为 {key,value} 串),无需再映射。
 * 编辑经 useUpdatePolicies(PUT)热生效 + 落盘;不可达/非 yaml 引擎 → 诚实空态。刷新放缓(60s)。
 */
export function usePolicies() {
  return useQuery<PolicySet | null>({
    queryKey: KEY,
    queryFn: () => api<PolicySet | null>('/policies'),
    refetchInterval: 60_000,
  })
}

/**
 * 编辑策略(PUT /policies,需 policies.manage)。提交后端校验通过即热生效 + 落盘,
 * 用返回的新文档直接回填缓存(版本号 +1),无需等下一次轮询。非法策略后端返回 400 文案。
 */
export function useUpdatePolicies() {
  const qc = useQueryClient()
  return useMutation<PolicySet, Error, PolicySetWrite>({
    mutationFn: (body) =>
      api<PolicySet>('/policies', { method: 'PUT', body: JSON.stringify(body) }),
    onSuccess: (next) => qc.setQueryData(KEY, next),
  })
}
