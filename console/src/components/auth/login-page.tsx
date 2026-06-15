import { useState, type ComponentType, type ReactNode } from 'react'
import { Check, Eye, EyeOff, Lock, ShieldCheck, User, type LucideProps } from 'lucide-react'
import { Button } from '@/components/ui'
import { cn } from '@/lib/utils'
import { useAuth } from '@/lib/auth'

/** 带前置图标的输入行(登录专用,比通用 Input 更大、更聚焦) */
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
      <span className="mb-1.5 block text-[13px] font-medium text-ink-2">{label}</span>
      <span
        className={cn(
          'flex h-11 items-center gap-2.5 rounded-[10px] border border-line-2 bg-surface/80 px-3',
          'transition-colors hover:border-line-3',
          'focus-within:border-accent focus-within:ring-2 focus-within:ring-accent/30',
        )}
      >
        <Icon className="h-[17px] w-[17px] shrink-0 text-ink-mute" strokeWidth={1.8} />
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
      {/* 左:登录面板(玻璃) */}
      <div className="w-full shrink-0 md:w-[42%] md:min-w-[420px] md:max-w-[560px]">
        <div className="glass-panel relative m-4 flex h-[calc(100%-32px)] flex-col rounded-[24px] px-8 py-9 sm:px-11">
          {/* 品牌锁 */}
          <div className="relative z-10 flex items-center gap-2.5">
            <span className="grid h-9 w-9 place-items-center rounded-[11px] bg-accent shadow-[0_6px_14px_-6px_rgba(59,110,246,0.6)]">
              <ShieldCheck className="h-[19px] w-[19px] text-white" strokeWidth={1.9} />
            </span>
            <span className="leading-tight">
              <span className="block text-[16px] font-bold tracking-[-0.01em]">
                枢衡 <span className="font-medium text-ink-3">Fulcrum</span>
              </span>
              <span className="block text-[12.5px] text-ink-mute">智能体安全中台</span>
            </span>
          </div>

          {/* 表单(垂直居中) */}
          <form onSubmit={submit} className="relative z-10 mx-auto my-auto w-full max-w-[348px]">
            <h1 className="text-[24px] font-bold tracking-[-0.02em] text-ink">登录控制台</h1>
            <p className="mt-1.5 text-[14px] text-ink-3">私有化部署 · 单租户 · 仅限授权访问</p>

            <div className="mt-7 space-y-4">
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
                    className="focus-ring grid h-7 w-7 shrink-0 place-items-center rounded-[7px] text-ink-mute transition-colors hover:bg-surface-2 hover:text-ink-2"
                  >
                    {show ? (
                      <EyeOff className="h-[16px] w-[16px]" strokeWidth={1.8} />
                    ) : (
                      <Eye className="h-[16px] w-[16px]" strokeWidth={1.8} />
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
                className="focus-ring flex items-center gap-2 text-[13.5px] text-ink-2"
              >
                <span
                  className={cn(
                    'grid h-[16px] w-[16px] place-items-center rounded-[5px] border transition-colors',
                    remember
                      ? 'border-accent bg-accent text-white'
                      : 'border-line-3 bg-surface',
                  )}
                >
                  {remember && <Check className="h-3 w-3" strokeWidth={3} />}
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
            <p className="mt-3 min-h-[18px] text-[13px] text-crit">{error}</p>

            <Button
              type="submit"
              variant="primary"
              disabled={loading}
              className="mt-1 h-11 w-full text-[15px]"
            >
              {loading ? '正在登录…' : '登录'}
            </Button>
          </form>

          {/* 页脚 */}
          <p className="relative z-10 text-center text-[12px] text-ink-mute">
            © 2026 枢衡 Fulcrum · 内部安全系统,登录行为已审计
          </p>
        </div>
      </div>

      {/* 右:展示区(背景图透出,叠一条克制的定位标语) */}
      <div className="relative hidden flex-1 md:block">
        <div className="absolute bottom-14 left-14 right-14 max-w-[560px]">
          <p className="text-[34px] font-bold leading-[1.18] tracking-[-0.02em] text-ink/85">
            为政企智能体
            <br />
            建立可信安全边界
          </p>
          <p className="mt-3.5 text-[15px] leading-relaxed text-ink-2/75">
            输入检测 · 工具管控 · 审计溯源 · 评测验证 —— 在智能体外侧形成可验证的治理闭环。
          </p>
        </div>
      </div>
    </div>
  )
}
