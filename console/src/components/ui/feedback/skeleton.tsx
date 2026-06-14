import { cn } from '@/lib/utils'

export function Skeleton({ className }: { className?: string }) {
  return (
    <div
      className={cn('rounded-md bg-surface-2', className)}
      style={{
        backgroundImage:
          'linear-gradient(90deg, var(--color-surface-2) 25%, var(--color-inset) 37%, var(--color-surface-2) 63%)',
        backgroundSize: '400% 100%',
        animation: 'shimmer 1.3s ease-in-out infinite',
      }}
    />
  )
}
