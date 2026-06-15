import * as RDialog from '@radix-ui/react-dialog'
import { X } from 'lucide-react'
import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

export interface DialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: ReactNode
  description?: ReactNode
  children: ReactNode
  /** 底部操作区(按钮等) */
  footer?: ReactNode
  /** 内容最大宽度类,默认 max-w-lg */
  widthClassName?: string
}

/** Linear 式模态:磨砂浮层 + 居中卡片,标题/正文/底部三段式。 */
export function Dialog({
  open,
  onOpenChange,
  title,
  description,
  children,
  footer,
  widthClassName = 'max-w-lg',
}: DialogProps) {
  return (
    <RDialog.Root open={open} onOpenChange={onOpenChange}>
      <RDialog.Portal>
        <RDialog.Overlay className="fixed inset-0 z-50 bg-ink/25 backdrop-blur-[2px]" />
        <RDialog.Content
          className={cn(
            'fixed left-1/2 top-1/2 z-50 flex max-h-[88vh] w-[calc(100vw-2rem)] -translate-x-1/2 -translate-y-1/2 flex-col',
            'rounded-[16px] border border-line bg-surface shadow-pop',
            'data-[state=open]:animate-[pop-in_0.16s_var(--ease-out-quart)]',
            widthClassName,
          )}
        >
          <div className="flex items-start gap-3 border-b border-line px-5 py-3.5">
            <div className="min-w-0 flex-1">
              <RDialog.Title className="text-[16px] font-semibold tracking-[-0.01em] text-ink">
                {title}
              </RDialog.Title>
              {description && (
                <RDialog.Description className="mt-0.5 text-[13px] text-ink-3">
                  {description}
                </RDialog.Description>
              )}
            </div>
            <RDialog.Close className="focus-ring -mr-1 grid h-7 w-7 shrink-0 place-items-center rounded-[8px] text-ink-mute transition-colors hover:bg-surface-2 hover:text-ink-2">
              <X className="h-[16px] w-[16px]" strokeWidth={2} />
            </RDialog.Close>
          </div>

          <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">{children}</div>

          {footer && (
            <div className="flex items-center justify-end gap-2 border-t border-line px-5 py-3">
              {footer}
            </div>
          )}
        </RDialog.Content>
      </RDialog.Portal>
    </RDialog.Root>
  )
}
