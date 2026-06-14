import { Toaster as Sonner } from 'sonner'

/** 全局 toast 容器,套用枢衡视觉令牌 */
export function Toaster() {
  return (
    <Sonner
      position="bottom-right"
      gap={10}
      toastOptions={{
        classNames: {
          toast:
            '!rounded-md !bg-surface !text-ink !shadow-pop !border !border-line !font-sans',
          title: '!text-[13px] !font-semibold',
          description: '!text-[11px] !text-ink-3',
          error: '!border-l-[3px] !border-l-crit',
        },
      }}
    />
  )
}

export { toast } from 'sonner'
