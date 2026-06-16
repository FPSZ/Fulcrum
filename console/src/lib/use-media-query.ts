import { useEffect, useState } from 'react'

/** 订阅一个 CSS 媒体查询,返回是否命中(SSR 安全)。 */
export function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(() =>
    typeof window !== 'undefined' ? window.matchMedia(query).matches : false,
  )
  useEffect(() => {
    const mq = window.matchMedia(query)
    const on = () => setMatches(mq.matches)
    on()
    mq.addEventListener('change', on)
    return () => mq.removeEventListener('change', on)
  }, [query])
  return matches
}

/** <768px 视为移动端(单手管理场景);与 Tailwind `md` 断点对齐。 */
export function useIsMobile(): boolean {
  return useMediaQuery('(max-width: 767px)')
}
