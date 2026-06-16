import { type ReactNode, useEffect } from 'react'
import { AnimatePresence, motion } from 'motion/react'
import { Shield, X } from 'lucide-react'
import { IconButton } from '@/components/ui'

/**
 * 移动端导航抽屉 —— 从左滑出,承载完整分组侧栏。
 * 桌面端不渲染(由 AppShell 控制 md:hidden 语义);打开时锁背景滚动。
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
    <AnimatePresence>
      {open && (
        <div className="fixed inset-0 z-50 md:hidden">
          <motion.div
            className="absolute inset-0 bg-ink/30 backdrop-blur-[2px]"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            onClick={onClose}
          />
          <motion.aside
            className="absolute inset-y-0 left-0 flex w-[270px] max-w-[82vw] flex-col bg-canvas shadow-pop"
            initial={{ x: '-100%' }}
            animate={{ x: 0 }}
            exit={{ x: '-100%' }}
            transition={{ type: 'tween', duration: 0.26, ease: [0.25, 1, 0.5, 1] }}
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
          </motion.aside>
        </div>
      )}
    </AnimatePresence>
  )
}
