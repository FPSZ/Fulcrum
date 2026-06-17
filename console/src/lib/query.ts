import { QueryClient } from '@tanstack/react-query'

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
        const msg = error instanceof Error ? error.message : ''
        if (msg.includes('无权限') || msg.includes('未登录')) return false
        return failureCount < 2
      },
    },
  },
})
