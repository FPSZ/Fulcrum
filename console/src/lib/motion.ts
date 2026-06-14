import type { Transition, Variants } from 'motion/react'

/** 全局统一的过渡曲线 —— 丝滑、克制、不弹跳过度 */
export const ease = {
  /** 标准缓出,用于绝大多数进入/位移 */
  out: [0.25, 1, 0.5, 1] as const,
  /** 轻微回弹,用于强调出现的元素 */
  spring: { type: 'spring', stiffness: 520, damping: 38, mass: 0.9 } as Transition,
}

/**
 * 详情内容在选择切换时的淡入。
 * 只动 opacity、不动 transform —— 静止态不残留合成层,Windows 低 DPI 下文字
 * 仍走 ClearType 次像素渲染,不会发糊。
 */
export const detailSwap: Variants = {
  initial: { opacity: 0 },
  animate: { opacity: 1, transition: { duration: 0.2, ease: ease.out } },
  exit: { opacity: 0, transition: { duration: 0.1, ease: ease.out } },
}

/** 列表行/分组进入时的轻微浮现 */
export const riseIn: Variants = {
  initial: { opacity: 0, y: 4 },
  animate: { opacity: 1, y: 0 },
}

/** 分组容器:子项错位浮现 */
export const stagger: Variants = {
  animate: { transition: { staggerChildren: 0.018, delayChildren: 0.02 } },
}
