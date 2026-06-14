import { cn } from '@/lib/utils'
import type { Disposition } from './types'

/**
 * 分组状态图标:处置类型的图形表意。
 * 用 SVG 矢量绘制(非 CSS 边框/conic-gradient),低 DPI 下也是正圆居中,不会发歪。
 */
export function DispositionIcon({ disp, className }: { disp: Disposition; className?: string }) {
  const cls = cn('h-[15px] w-[15px] shrink-0', className)
  switch (disp) {
    case 'block':
      return (
        <svg viewBox="0 0 16 16" className={cls} aria-hidden>
          <circle cx="8" cy="8" r="7" fill="var(--color-crit)" />
          <path
            d="M5.4 5.4l5.2 5.2M10.6 5.4l-5.2 5.2"
            stroke="#fff"
            strokeWidth="1.7"
            strokeLinecap="round"
          />
        </svg>
      )
    case 'allow':
      return (
        <svg viewBox="0 0 16 16" className={cls} aria-hidden>
          <circle cx="8" cy="8" r="7" fill="var(--color-ok)" />
          <path
            d="M4.8 8.2l2.1 2.1 4.3-4.6"
            fill="none"
            stroke="#fff"
            strokeWidth="1.7"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      )
    case 'approve':
      return (
        <svg viewBox="0 0 16 16" className={cls} aria-hidden>
          <circle cx="8" cy="8" r="6.2" fill="none" stroke="var(--color-high)" strokeWidth="1.7" />
          {/* 右半圆填充 = 进行中/待审批 */}
          <path d="M8 8 L8 1.8 A6.2 6.2 0 0 1 8 14.2 Z" fill="var(--color-high)" />
        </svg>
      )
    case 'sanitize':
      return (
        <svg viewBox="0 0 16 16" className={cls} aria-hidden>
          <circle cx="8" cy="8" r="6.2" fill="none" stroke="var(--color-info)" strokeWidth="1.7" />
          <circle cx="8" cy="8" r="2.5" fill="var(--color-info)" />
        </svg>
      )
  }
}
