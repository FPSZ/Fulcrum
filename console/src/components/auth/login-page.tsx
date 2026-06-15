import { useState, type ComponentType, type ReactNode } from 'react'
import {
  ArrowRight,
  Check,
  Eye,
  EyeOff,
  Loader2,
  Lock,
  ShieldCheck,
  User,
  type LucideProps,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useAuth } from '@/lib/auth'

/** 带前置图标的输入行(登录专用:更高、柔填充、聚焦时柔光晕) */
function Field({
  icon: Icon,
  label,
  trailing,
  children,
}: {
  icon: ComponentType<LucideProps>
  label: string
  trailing?: ReactNode
  children: ReactNode
}) {
  return (
    <label className="block">
      <span className="mb-2 block text-[12.5px] font-medium tracking-[0.01em] text-ink-2">
        {label}
      </span>
      <span
        className={cn(
          'flex h-12 items-center gap-3 rounded-[13px] border border-line-2 bg-white/55 px-3.5',
          'shadow-[inset_0_1px_0_rgba(255,255,255,0.7)] transition-all duration-150',
          'hover:border-line-3 hover:bg-white/70',
          'focus-within:border-accent focus-within:bg-white focus-within:ring-4 focus-within:ring-accent/14',
        )}
      >
        <Icon className="h-[18px] w-[18px] shrink-0 text-ink-mute" strokeWidth={1.8} />
        {children}
        {trailing}
      </span>
    </label>
  )
}

export function LoginPage() {
  const { login } = useAuth()
  const [account, setAccount] = useState('')
  const [password, setPassword] = useState('')
  const [show, setShow] = useState(false)
  const [remember, setRemember] = useState(true)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await login(account, password)
      // 成功后不复位 loading:登录页马上向上滑走
    } catch (err) {
      setError(err instanceof Error ? err.message : '登录失败')
      setLoading(false)
    }
  }

  return (
    <div className="flex h-full w-full">
      {/* 左:登录面板(干净亮玻璃) */}
      <div className="w-full shrink-0 md:w-[44%] md:min-w-[440px] md:max-w-[600px]">
        <div
          className={cn(
            'relative m-4 flex h-[calc(100%-32px)] flex-col rounded-[28px] px-9 py-10 sm:px-14',
            'border border-white/65 bg-white/72 backdrop-blur-2xl',
            'shadow-[0_36px_90px_-36px_rgba(26,36,70,0.5),0_8px_24px_-16px_rgba(26,36,70,0.25),inset_0_1.5px_0_rgba(255,255,255,0.95)]',
          )}
        >
          {/* 顶角受光高光 */}
          <div
            aria-hidden
            className="pointer-events-none absolute inset-0 rounded-[28px]"
            style={{
              background:
                'radial-gradient(60% 32% at 0% 0%, rgba(255,255,255,0.5), transparent 70%)',
            }}
          />

          {/* 品牌锁 */}
          <div className="relative flex items-center gap-3">
            <span className="grid h-10 w-10 place-items-center rounded-[13px] bg-[linear-gradient(160deg,#5680f8,#3b6ef6_60%,#2f5fe0)] shadow-[0_8px_18px_-6px_rgba(59,110,246,0.7),inset_0_1px_0_rgba(255,255,255,0.4)]">
              <ShieldCheck className="h-[21px] w-[21px] text-white" strokeWidth={2} />
            </span>
            <span className="leading-tight">
              <span className="block text-[16px] font-bold tracking-[-0.01em]">
                枢衡 <span className="font-medium text-ink-3">Fulcrum</span>
              </span>
              <span className="block text-[12.5px] text-ink-mute">智能体安全中台</span>
            </span>
          </div>

          {/* 表单(垂直居中) */}
          <form onSubmit={submit} className="relative mx-auto my-auto w-full max-w-[352px]">
            <h1 className="text-[30px] font-bold leading-[1.1] tracking-[-0.025em] text-ink">
              欢迎回来
            </h1>

            <div className="mt-8 space-y-4">
              <Field icon={User} label="账号">
                <input
                  type="text"
                  autoFocus
                  autoComplete="username"
                  value={account}
                  onChange={(e) => setAccount(e.target.value)}
                  placeholder="请输入账号"
                  className="h-full w-full bg-transparent text-[15px] text-ink outline-none placeholder:text-ink-mute"
                />
              </Field>

              <Field
                icon={Lock}
                label="口令"
                trailing={
                  <button
                    type="button"
                    onClick={() => setShow((v) => !v)}
                    aria-label={show ? '隐藏口令' : '显示口令'}
                    className="focus-ring grid h-8 w-8 shrink-0 place-items-center rounded-[9px] text-ink-mute transition-colors hover:bg-surface-2 hover:text-ink-2"
                  >
                    {show ? (
                      <EyeOff className="h-[17px] w-[17px]" strokeWidth={1.8} />
                    ) : (
                      <Eye className="h-[17px] w-[17px]" strokeWidth={1.8} />
                    )}
                  </button>
                }
              >
                <input
                  type={show ? 'text' : 'password'}
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="请输入口令"
                  className="h-full w-full bg-transparent text-[15px] text-ink outline-none placeholder:text-ink-mute"
                />
              </Field>
            </div>

            {/* 记住登录 / 忘记口令 */}
            <div className="mt-4 flex items-center justify-between">
              <button
                type="button"
                role="checkbox"
                aria-checked={remember}
                onClick={() => setRemember((v) => !v)}
                className="focus-ring group flex items-center gap-2 text-[13.5px] text-ink-2"
              >
                <span
                  className={cn(
                    'grid h-[17px] w-[17px] place-items-center rounded-[6px] border transition-all duration-150',
                    remember
                      ? 'border-accent bg-accent text-white shadow-[0_2px_6px_-2px_rgba(59,110,246,0.7)]'
                      : 'border-line-3 bg-white/70 group-hover:border-ink-mute',
                  )}
                >
                  {remember && <Check className="h-3 w-3" strokeWidth={3.2} />}
                </span>
                记住登录
              </button>
              <button
                type="button"
                className="focus-ring rounded text-[13.5px] font-medium text-accent-ink transition-colors hover:text-accent-hover"
              >
                忘记口令?
              </button>
            </div>

            {/* 错误提示(占位高度,避免抖动) */}
            <p className="mt-3.5 min-h-[18px] text-[13px] text-crit">{error}</p>

            {/* 主按钮:柔和渐变 + 同色投影 + 微浮起 */}
            <button
              type="submit"
              disabled={loading}
              className={cn(
                'focus-ring group relative flex h-12 w-full items-center justify-center gap-2 overflow-hidden rounded-[13px] text-[15px] font-semibold text-white',
                'bg-[linear-gradient(180deg,#5882f9_0%,#3b6ef6_55%,#2f5fe0_100%)]',
                'shadow-[0_10px_26px_-8px_rgba(59,110,246,0.6),inset_0_1px_0_rgba(255,255,255,0.32)]',
                'transition-[transform,filter,box-shadow] duration-150',
                'hover:-translate-y-px hover:brightness-[1.05] hover:shadow-[0_14px_32px_-8px_rgba(59,110,246,0.62)]',
                'active:translate-y-0 active:brightness-95 disabled:pointer-events-none disabled:opacity-80',
              )}
            >
              {loading ? (
                <>
                  <Loader2 className="h-[18px] w-[18px] animate-spin" strokeWidth={2.2} />
                  正在登录…
                </>
              ) : (
                <>
                  登录
                  <ArrowRight
                    className="h-[18px] w-[18px] transition-transform duration-200 group-hover:translate-x-0.5"
                    strokeWidth={2}
                  />
                </>
              )}
            </button>
          </form>
        </div>
      </div>

      {/* 右:空展示区(背景图透出) */}
      <div className="hidden flex-1 md:block" />
    </div>
  )
}
