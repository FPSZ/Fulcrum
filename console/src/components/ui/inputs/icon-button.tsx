import * as React from 'react'
import { Button, type ButtonProps } from './button'
import { Tooltip } from '../overlay/tooltip'

export interface IconButtonProps extends Omit<ButtonProps, 'size'> {
  /** 无障碍标签;同时作为 tooltip 文案 */
  label: string
  tooltip?: boolean
}

/** 仅图标按钮:强制 aria-label,可选 tooltip */
export const IconButton = React.forwardRef<HTMLButtonElement, IconButtonProps>(
  ({ label, tooltip = true, variant = 'ghost', children, ...props }, ref) => {
    const btn = (
      <Button ref={ref} size="icon" variant={variant} aria-label={label} {...props}>
        {children}
      </Button>
    )
    return tooltip ? <Tooltip content={label}>{btn}</Tooltip> : btn
  },
)
IconButton.displayName = 'IconButton'
