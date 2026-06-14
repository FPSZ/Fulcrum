import * as RS from '@radix-ui/react-switch'
import { cn } from '@/lib/utils'

export function Switch({ className, ...props }: RS.SwitchProps) {
  return (
    <RS.Root
      className={cn(
        'focus-ring inline-flex h-[18px] w-[30px] shrink-0 items-center rounded-full bg-surface-2 transition-colors',
        'data-[state=checked]:bg-accent disabled:cursor-not-allowed disabled:opacity-50',
        className,
      )}
      {...props}
    >
      <RS.Thumb className="block h-[14px] w-[14px] translate-x-0.5 rounded-full bg-white shadow-xs transition-transform duration-150 data-[state=checked]:translate-x-[14px]" />
    </RS.Root>
  )
}
