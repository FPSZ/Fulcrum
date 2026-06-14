import * as RA from '@radix-ui/react-avatar'
import { cn } from '@/lib/utils'

export interface AvatarProps {
  fallback: string
  src?: string
  className?: string
}

export function Avatar({ fallback, src, className }: AvatarProps) {
  return (
    <RA.Root
      className={cn(
        'inline-grid h-7 w-7 shrink-0 place-items-center overflow-hidden rounded-full',
        'bg-accent/10 text-[11px] font-semibold text-accent-ink',
        className,
      )}
    >
      {src && <RA.Image src={src} className="h-full w-full object-cover" />}
      <RA.Fallback>{fallback}</RA.Fallback>
    </RA.Root>
  )
}
