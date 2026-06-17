import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api/client'
import type { ScanReport } from './data'

/**
 * 供应链扫描(接真后端 GET /supply/scans)。对配置目录的组件 manifest 跑静态扫描评级;
 * 后端 DTO 与前端 ScanReport 同构,无需再映射。组件登记是离线关切,刷新放缓(60s)。
 * 无权限/不可达/空 → 调用方回退演示 seed。
 */
export function useSupplyScans() {
  return useQuery<ScanReport[]>({
    queryKey: ['supply', 'scans'],
    queryFn: () => api<ScanReport[]>('/supply/scans'),
    refetchInterval: 60_000,
  })
}
