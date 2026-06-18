import { type ReactNode, useEffect, useRef, useState } from 'react'
import { cn } from '@/lib/utils'
import { AppFooter } from './app-footer'

/** 每帧逼近系数:越小越"重",滑动越绵长丝滑(0.14 ≈ 高级缓动) */
const LERP = 0.14
/** 收束到目标的阈值 */
const SNAP = 0.4

/**
 * 页脚揭示容器(仅桌面 / 系统页)
 * ─────────────────────────────────────────────────────────────
 * 结构:页脚铺在底层 → 内容卡盖在其上(z 更高)。
 * 交互:页面内滚轮照常原生滚动;一旦内部滚动到底再继续下滑,
 *      接管滚轮,用 rAF lerp 把内容卡 translateY 上滑,丝滑带缓动惯性,
 *      不随滚轮一格一格跳。向上滑时先把页脚收回,再恢复原生滚动。
 * 物理量全部存在 ref 里逐帧改 transform,绝不每帧 setState(零重渲染)。
 */
export function FooterReveal({
  children,
  onNavigate,
  navKey,
}: {
  children: ReactNode
  onNavigate?: (id: string) => void
  /** 当前页标识:切页时把已揭示的页脚归零,避免它挂在新页上 */
  navKey?: string
}) {
  const wrapRef = useRef<HTMLDivElement>(null)
  const cardRef = useRef<HTMLDivElement>(null)
  const footerRef = useRef<HTMLDivElement>(null)

  const target = useRef(0) // 目标揭示量(px)
  const offset = useRef(0) // 当前揭示量(px,逐帧逼近 target)
  const maxRef = useRef(0) // 页脚高度 = 最大揭示量
  const raf = useRef(0)
  const [revealed, setRevealed] = useState(false) // 仅用于切换页脚可点击态

  /** 找事件目标到容器之间最近的、真正可滚动的祖先 */
  const scrollerAt = (start: EventTarget | null): HTMLElement | null => {
    let el = start as HTMLElement | null
    const stop = wrapRef.current
    while (el && el !== stop) {
      const oy = getComputedStyle(el).overflowY
      if ((oy === 'auto' || oy === 'scroll') && el.scrollHeight > el.clientHeight + 1) return el
      el = el.parentElement
    }
    return null
  }

  /** 该位置是否处于"免揭示区"(生产力工作面:其滚动绝不牵动页脚) */
  const inNoRevealZone = (start: EventTarget | null): boolean => {
    let el = start as HTMLElement | null
    const stop = wrapRef.current
    while (el && el !== stop) {
      if (el.hasAttribute('data-no-reveal')) return true
      el = el.parentElement
    }
    return false
  }

  const render = () => {
    const max = maxRef.current || 1
    const p = Math.min(1, offset.current / max)
    if (cardRef.current) {
      if (offset.current > 0) {
        // 揭示中:升为合成层并逐帧上滑(动画期文字短暂合成可接受)
        cardRef.current.style.willChange = 'transform'
        cardRef.current.style.transform = `translate3d(0,${-offset.current}px,0)`
      } else {
        // 静止态:撤掉合成层与位移,恢复 ClearType 亚像素抗锯齿
        // —— 否则常驻 transform/will-change 会让这张包住全部内容的卡在
        // Windows 低 DPI(1080p,DPR=1)下改用灰度 AA,整页文字发虚(见 motion.ts 同则)。
        cardRef.current.style.willChange = 'auto'
        cardRef.current.style.transform = 'none'
      }
    }
    if (footerRef.current) {
      // 揭示量映射成 透明度(避免卡片半透明时透出残影)+ 轻微视差上收
      footerRef.current.style.opacity = String(Math.min(1, p * 1.25))
      footerRef.current.style.transform = `translate3d(0,${(1 - p) * 26}px,0)`
    }
  }

  const tick = () => {
    const next = offset.current + (target.current - offset.current) * LERP
    offset.current = Math.abs(target.current - next) < SNAP ? target.current : next
    render()
    if (offset.current !== target.current) {
      raf.current = requestAnimationFrame(tick)
    } else {
      raf.current = 0
    }
  }

  const kick = () => {
    if (!raf.current) raf.current = requestAnimationFrame(tick)
  }

  const setTarget = (v: number) => {
    target.current = Math.max(0, Math.min(maxRef.current, v))
    setRevealed(target.current > 0)
    kick()
  }

  const backToTop = () => {
    setTarget(0)
    // 顺手把内容滚回顶部(任意可滚动后代)
    const sc = wrapRef.current?.querySelector<HTMLElement>(
      '[class*="overflow-y-auto"],[class*="overflow-auto"]',
    )
    sc?.scrollTo({ top: 0, behavior: 'smooth' })
  }

  // 切页:立即把页脚归零,不让它挂在新页面上
  useEffect(() => {
    target.current = 0
    offset.current = 0
    if (raf.current) {
      cancelAnimationFrame(raf.current)
      raf.current = 0
    }
    render()
    setRevealed(false)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [navKey])

  useEffect(() => {
    const wrap = wrapRef.current
    if (!wrap) return

    const onWheel = (e: WheelEvent) => {
      maxRef.current = footerRef.current?.offsetHeight ?? 0
      if (maxRef.current <= 0) return // 页脚未渲染(移动端)→ 全程原生滚动
      const dy = e.deltaY
      const t = target.current

      // 页脚已展开:任何方向都先驱动页脚(它有最高优先级)
      if (t > 0) {
        e.preventDefault()
        setTarget(t + dy)
        return
      }
      // 免揭示区(生产力工作面)→ 全程交给原生滚动,绝不揭示页脚
      if (inNoRevealZone(e.target)) return
      // 未展开:仅当落到内部滚动底部、且继续下滑时开始揭示
      if (dy > 0) {
        const sc = scrollerAt(e.target)
        const atBottom = !sc || sc.scrollTop + sc.clientHeight >= sc.scrollHeight - 1
        if (atBottom) {
          e.preventDefault()
          setTarget(t + dy)
        }
      }
      // 其余情况:不拦截,交给浏览器原生滚动(此时手感照常)
    }

    wrap.addEventListener('wheel', onWheel, { passive: false })
    return () => {
      wrap.removeEventListener('wheel', onWheel)
      if (raf.current) cancelAnimationFrame(raf.current)
    }
  }, [])

  return (
    <div ref={wrapRef} className="relative flex min-h-0 flex-1 flex-col overflow-hidden">
      {/* 页脚:底层,仅桌面;初始透明,被内容卡盖住,卡上滑时露出 */}
      <div
        ref={footerRef}
        aria-hidden={!revealed}
        className={cn(
          'absolute inset-x-0 bottom-0 z-0 hidden h-auto opacity-0 md:block',
          revealed ? 'pointer-events-auto' : 'pointer-events-none',
        )}
      >
        <AppFooter onNavigate={onNavigate} onBackToTop={backToTop} />
      </div>

      {/* 内容卡:上层,逐帧 translateY 上滑揭示页脚。
          底边一道向下柔影:卡上滑时落在页脚上,呈现"页面浮在页脚之上"的层次 */}
      <div
        ref={cardRef}
        className="relative z-10 flex min-h-0 flex-1 flex-col shadow-[0_16px_34px_-24px_rgba(20,28,56,0.2)]"
      >
        {children}
      </div>
    </div>
  )
}
