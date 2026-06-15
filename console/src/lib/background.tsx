import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'

/** 背景图(放在 public/bg/)。要轮换时往这里加条目即可,顶栏切换按钮会自动出现。 */
export const BACKGROUNDS = [{ src: '/bg/bg1.jpg', name: '晨光' }]

const KEY = 'fulcrum.bg'

interface BgValue {
  index: number
  current: (typeof BACKGROUNDS)[number]
  cycle: () => void
}
const Ctx = createContext<BgValue | null>(null)

export function BackgroundProvider({ children }: { children: ReactNode }) {
  const [index, setIndex] = useState(() => {
    const v = Number(localStorage.getItem(KEY))
    return Number.isInteger(v) && v >= 0 && v < BACKGROUNDS.length ? v : 0
  })
  useEffect(() => {
    localStorage.setItem(KEY, String(index))
  }, [index])
  const cycle = () => setIndex((i) => (i + 1) % BACKGROUNDS.length)
  return <Ctx.Provider value={{ index, current: BACKGROUNDS[index], cycle }}>{children}</Ctx.Provider>
}

export function useBackground(): BgValue {
  const c = useContext(Ctx)
  if (!c) throw new Error('useBackground 必须在 BackgroundProvider 内使用')
  return c
}

/**
 * 全屏背景图层:在玻璃面板之下,切换时柔和淡入。
 * `blurred` 为真时背景在约 1s 内柔和模糊(登录页清晰 → 进入主控制台后变模糊)。
 * scale(1.08) 把模糊产生的透明边推出视口,避免露出底层渐变接缝。
 */
export function BackgroundLayer({ blurred = false }: { blurred?: boolean }) {
  const { index, current } = useBackground()
  return (
    <div aria-hidden className="fixed inset-0 -z-10 overflow-hidden">
      <div
        key={index}
        className="absolute inset-0 bg-cover bg-center"
        style={{
          backgroundImage: `url(${current.src})`,
          transform: 'scale(1.08)',
          filter: blurred ? 'blur(15px) saturate(116%)' : 'blur(0px)',
          transition: 'filter 900ms cubic-bezier(0.25, 1, 0.5, 1) 150ms',
          animation: 'bg-fade 0.5s ease',
        }}
      />
    </div>
  )
}
