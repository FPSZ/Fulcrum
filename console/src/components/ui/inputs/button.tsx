import * as React from 'react'
import { Slot } from '@radix-ui/react-slot'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const button = cva(
  'inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-sm font-medium select-none ' +
    'transition-[background-color,border-color,box-shadow,transform,color] duration-150 ease-[var(--ease-out-quart)] ' +
    'focus-ring active:scale-[0.985] disabled:pointer-events-none disabled:opacity-50',
  {
    variants: {
      variant: {
        primary: 'bg-accent text-white shadow-xs hover:bg-accent-hover',
        secondary:
          'bg-surface text-ink-2 border border-line-2 hover:bg-surface-2 hover:border-line-3',
        ghost: 'text-ink-3 hover:bg-surface-2 hover:text-ink-2',
        danger: 'bg-crit text-white shadow-xs hover:brightness-110',
      },
      size: {
        sm: 'h-7 px-2.5 text-[14px]',
        md: 'h-8 px-3 text-[14px]',
        icon: 'h-8 w-8',
      },
    },
    defaultVariants: { variant: 'secondary', size: 'md' },
  },
)

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof button> {
  asChild?: boolean
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : 'button'
    return <Comp ref={ref} className={cn(button({ variant, size }), className)} {...props} />
  },
)
Button.displayName = 'Button'

export { button as buttonVariants }
