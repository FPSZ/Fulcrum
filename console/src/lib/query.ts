import { QueryClient } from '@tanstack/react-query'

import { ApiError } from '@/lib/api/client'

/**
 * 全站 TanStack Query 客户端 —— 前后端对接的查询地基。
 *
 * 安全控制台的数据多为「实时镜像」性质:默认较短的新鲜期 + 失焦重取关闭(避免切窗狂刷),
 * 鉴权类错误(401/403)不重试(重试也只会继续被后端挡下)。各页可按需覆盖。
 */
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 10_000,
      refetchOnWindowFocus: false,
      retry: (failureCount, error) => {
        // 鉴权类(401 未登录 / 403 无权限)不重试 —— 按状态码判定,不匹配本地化文案。
        if (error instanceof ApiError && (error.status === 401 || error.status === 403)) return false
        return failureCount < 2
      },
    },
  },
})
