import * as RSel from '@radix-ui/react-select'
import { Check, ChevronDown } from 'lucide-react'
import { cn } from '@/lib/utils'

export interface SelectOption {
  value: string
  label: string
}

export interface SelectProps {
  value?: string
  defaultValue?: string
  onValueChange?: (value: string) => void
  options: SelectOption[]
  placeholder?: string
  disabled?: boolean
  className?: string
}

export function Select({
  value,
  defaultValue,
  onValueChange,
  options,
  placeholder,
  disabled,
  className,
}: SelectProps) {
  return (
    <RSel.Root value={value} defaultValue={defaultValue} onValueChange={onValueChange} disabled={disabled}>
      <RSel.Trigger
        className={cn(
          'focus-ring inline-flex h-8 min-w-[140px] items-center gap-2 rounded-sm border border-line-2 bg-surface px-2.5 text-[15px] text-ink',
          'transition-colors hover:border-line-3 data-[placeholder]:text-ink-mute disabled:cursor-not-allowed disabled:opacity-50',
          className,
        )}
      >
        <RSel.Value placeholder={placeholder} />
        <RSel.Icon className="ml-auto">
          <ChevronDown className="h-3.5 w-3.5 text-ink-3" />
        </RSel.Icon>
      </RSel.Trigger>
      <RSel.Portal>
        <RSel.Content
          position="popper"
          sideOffset={6}
          className="z-50 overflow-hidden rounded-md border border-line bg-surface shadow-pop data-[state=open]:animate-[pop-in_0.14s_var(--ease-out-quart)]"
        >
          <RSel.Viewport className="p-1">
            {options.map((o) => (
              <RSel.Item
                key={o.value}
                value={o.value}
                className="focus-ring flex cursor-pointer select-none items-center gap-2 rounded-sm px-2 py-1.5 pr-8 text-[15px] text-ink-2 outline-none data-[highlighted]:bg-surface-2 data-[state=checked]:font-medium data-[state=checked]:text-ink"
              >
                <RSel.ItemText>{o.label}</RSel.ItemText>
                <RSel.ItemIndicator className="absolute right-2">
                  <Check className="h-3.5 w-3.5 text-accent" />
                </RSel.ItemIndicator>
              </RSel.Item>
            ))}
          </RSel.Viewport>
        </RSel.Content>
      </RSel.Portal>
    </RSel.Root>
  )
}
