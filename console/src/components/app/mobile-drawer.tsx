import { type ReactNode, useEffect } from 'react'
import { Shield, X } from 'lucide-react'
import { IconButton } from '@/components/ui'
import { cn } from '@/lib/utils'

/**
 * 移动端导航抽屉 —— 纯 CSS transition 滑入(translateX 由合成器处理,零逐帧 JS),
 * 常驻 DOM 避免开合时的挂载抖动;手机端流畅不掉帧。打开时锁背景滚动。
 */
export function MobileDrawer({
  open,
  onClose,
  children,
}: {
  open: boolean
  onClose: () => void
  children: ReactNode
}) {
  useEffect(() => {
    if (!open) return
    const prev = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.body.style.overflow = prev
    }
  }, [open])

  return (
    <div
      className={cn('fixed inset-0 z-50 md:hidden', !open && 'pointer-events-none')}
      aria-hidden={!open}
    >
      {/* 遮罩:仅淡入淡出(无 backdrop-filter,手机便宜) */}
      <div
        className={cn(
          'absolute inset-0 bg-ink/35 transition-opacity duration-300 ease-[var(--ease-out-quart)]',
          open ? 'opacity-100' : 'opacity-0',
        )}
        onClick={onClose}
      />
      {/* 面板:transform 滑动,合成层,不触发重排/重绘 */}
      <aside
        className={cn(
          'absolute inset-y-0 left-0 flex w-[270px] max-w-[82vw] flex-col bg-canvas shadow-pop',
          'transition-transform duration-300 ease-[var(--ease-out-quart)] [will-change:transform]',
          open ? 'translate-x-0' : '-translate-x-full',
        )}
      >
        <div className="flex h-14 shrink-0 items-center gap-2.5 border-b border-line px-4">
          <span className="grid h-8 w-8 shrink-0 place-items-center rounded-[10px] bg-accent shadow-[0_6px_14px_-6px_rgba(59,110,246,0.6)]">
            <Shield className="h-[17px] w-[17px] text-white" strokeWidth={1.9} />
          </span>
          <span className="text-[15.5px] font-bold tracking-[-0.01em]">
            枢衡 <span className="font-medium text-ink-3">Fulcrum</span>
          </span>
          <IconButton label="关闭菜单" variant="ghost" className="ml-auto h-9 w-9" onClick={onClose}>
            <X className="h-[18px] w-[18px]" />
          </IconButton>
        </div>
        {/* grid 让单一子项(侧栏)填满高度 → 其内部 nav 滚动、用户区贴底 */}
        <div className="grid min-h-0 flex-1">{children}</div>
      </aside>
    </div>
  )
}
