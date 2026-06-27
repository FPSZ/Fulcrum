import { useState, type ComponentType, type ReactNode } from 'react'
import {
  ArrowRight,
  Check,
  CheckCircle2,
  Eye,
  EyeOff,
  IdCard,
  Loader2,
  Lock,
  ShieldCheck,
  User,
  type LucideProps,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { requestAccount, useAuth } from '@/lib/auth'
import { useTranslation } from '@/lib/i18n'

type Mode = 'login' | 'apply'

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

/** 口令输入(带显隐切换),登录与申请共用 */
function PasswordField({
  label,
  value,
  onChange,
  placeholder,
  autoComplete,
  show,
  setShow,
}: {
  label: string
  value: string
  onChange: (v: string) => void
  placeholder: string
  autoComplete: string
  show: boolean
  setShow: (fn: (v: boolean) => boolean) => void
}) {
  const { t } = useTranslation()
  return (
    <Field
      icon={Lock}
      label={label}
      trailing={
        <button
          type="button"
          onClick={() => setShow((v) => !v)}
          aria-label={show ? t('auth.pwd.hide') : t('auth.pwd.show')}
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
        autoComplete={autoComplete}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="h-full w-full bg-transparent text-[15px] text-ink outline-none placeholder:text-ink-mute"
      />
    </Field>
  )
}

/** 主提交按钮:柔和渐变 + 同色投影 + 微浮起 */
function SubmitButton({
  loading,
  loadingText,
  text,
}: {
  loading: boolean
  loadingText: string
  text: string
}) {
  return (
    <button
      type="submit"
      disabled={loading}
      className={cn(
        'focus-ring group relative mt-5 flex h-12 w-full items-center justify-center gap-2 overflow-hidden rounded-[13px] text-[15px] font-semibold text-white',
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
          {loadingText}
        </>
      ) : (
        <>
          {text}
          <ArrowRight
            className="h-[18px] w-[18px] transition-transform duration-200 group-hover:translate-x-0.5"
            strokeWidth={2}
          />
        </>
      )}
    </button>
  )
}

/** 申请提交成功提示 */
function ApplySuccess({ onBack }: { onBack: () => void }) {
  const { t } = useTranslation()
  return (
    <div className="text-center">
      <span className="mx-auto grid h-14 w-14 place-items-center rounded-full bg-ok/12 text-ok">
        <CheckCircle2 className="h-8 w-8" strokeWidth={1.8} />
      </span>
      <h1 className="mt-5 text-[24px] font-bold tracking-[-0.02em] text-ink">
        {t('auth.apply.submitted')}
      </h1>
      <p className="mx-auto mt-2 max-w-[300px] text-[14px] leading-relaxed text-ink-3">
        {t('auth.apply.submitted_hint')}
      </p>
      <button
        type="button"
        onClick={onBack}
        className="focus-ring mt-6 rounded text-[14px] font-semibold text-accent-ink transition-colors hover:text-accent-hover"
      >
        {t('auth.back_to_login')}
      </button>
    </div>
  )
}

export function LoginPage() {
  const { login } = useAuth()
  const { t } = useTranslation()
  const [mode, setMode] = useState<Mode>('login')
  const [account, setAccount] = useState('')
  const [name, setName] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [show, setShow] = useState(false)
  const [remember, setRemember] = useState(true)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [applied, setApplied] = useState(false)

  const switchMode = (next: Mode) => {
    setMode(next)
    setError('')
    setPassword('')
    setConfirm('')
    setApplied(false)
  }

  const submitLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await login(account, password)
      // 成功后不复位 loading:登录页马上向上滑走
    } catch (err) {
      setError(err instanceof Error ? err.message : t('auth.error.login_failed'))
      setLoading(false)
    }
  }

  const submitApply = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    if (!name.trim() || !account.trim()) return setError(t('auth.error.name_account_required'))
    if (password.length < 8) return setError(t('auth.error.pwd_min'))
    if (password !== confirm) return setError(t('auth.error.pwd_mismatch'))
    setLoading(true)
    try {
      await requestAccount(account, password, name)
      setApplied(true)
    } catch (err) {
      setError(err instanceof Error ? err.message : t('auth.error.apply_failed'))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex h-full w-full">
      {/* 左:登录面板(干净亮玻璃) */}
      <div className="w-full shrink-0 md:w-[44%] md:min-w-[440px] md:max-w-[600px]">
        <div
          className={cn(
            'relative flex h-full flex-col px-6 py-9 sm:px-14 sm:py-10',
            'border-y border-r border-white/65 bg-white/72 backdrop-blur-2xl',
            'shadow-[0_36px_90px_-36px_rgba(26,36,70,0.5),0_8px_24px_-16px_rgba(26,36,70,0.25),inset_0_1.5px_0_rgba(255,255,255,0.95)]',
          )}
        >
          {/* 顶角受光高光 */}
          <div
            aria-hidden
            className="pointer-events-none absolute inset-0"
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
                {t('common.app.name')} <span className="font-medium text-ink-3">Fulcrum</span>
              </span>
              <span className="block text-[12.5px] text-ink-mute">{t('common.app.tagline')}</span>
            </span>
          </div>

          {/* 表单(垂直居中) */}
          <div className="relative mx-auto my-auto w-full max-w-[352px]">
            {applied ? (
              <ApplySuccess onBack={() => switchMode('login')} />
            ) : mode === 'login' ? (
              <form onSubmit={submitLogin}>
                <h1 className="text-[30px] font-bold leading-[1.1] tracking-[-0.025em] text-ink">
                  {t('auth.welcome')}
                </h1>
                <div className="mt-8 space-y-4">
                  <Field icon={User} label={t('auth.field.account')}>
                    <input
                      type="text"
                      autoFocus
                      autoComplete="username"
                      value={account}
                      onChange={(e) => setAccount(e.target.value)}
                      placeholder={t('auth.field.account_ph')}
                      className="h-full w-full bg-transparent text-[15px] text-ink outline-none placeholder:text-ink-mute"
                    />
                  </Field>
                  <PasswordField
                    label={t('auth.field.password')}
                    value={password}
                    onChange={setPassword}
                    placeholder={t('auth.field.password_ph')}
                    autoComplete="current-password"
                    show={show}
                    setShow={setShow}
                  />
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
                    {t('auth.remember')}
                  </button>
                  <button
                    type="button"
                    className="focus-ring rounded text-[13.5px] font-medium text-accent-ink transition-colors hover:text-accent-hover"
                  >
                    {t('auth.forgot')}
                  </button>
                </div>

                <p className="mt-3.5 min-h-[18px] text-[13px] text-crit">{error}</p>
                <SubmitButton
                  loading={loading}
                  loadingText={t('auth.logging_in')}
                  text={t('auth.login')}
                />
              </form>
            ) : (
              <form onSubmit={submitApply}>
                <h1 className="text-[30px] font-bold leading-[1.1] tracking-[-0.025em] text-ink">
                  {t('auth.apply_account')}
                </h1>
                <p className="mt-2 text-[13.5px] text-ink-3">{t('auth.apply_hint')}</p>
                <div className="mt-6 space-y-3.5">
                  <Field icon={IdCard} label={t('auth.field.name')}>
                    <input
                      type="text"
                      autoFocus
                      autoComplete="name"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      placeholder={t('auth.field.name_ph')}
                      className="h-full w-full bg-transparent text-[15px] text-ink outline-none placeholder:text-ink-mute"
                    />
                  </Field>
                  <Field icon={User} label={t('auth.field.account')}>
                    <input
                      type="text"
                      autoComplete="username"
                      value={account}
                      onChange={(e) => setAccount(e.target.value)}
                      placeholder={t('auth.field.account_apply_ph')}
                      className="h-full w-full bg-transparent text-[15px] text-ink outline-none placeholder:text-ink-mute"
                    />
                  </Field>
                  <PasswordField
                    label={t('auth.field.password')}
                    value={password}
                    onChange={setPassword}
                    placeholder={t('auth.field.pwd_min_ph')}
                    autoComplete="new-password"
                    show={show}
                    setShow={setShow}
                  />
                  <Field icon={Lock} label={t('auth.field.confirm_pwd')}>
                    <input
                      type={show ? 'text' : 'password'}
                      autoComplete="new-password"
                      value={confirm}
                      onChange={(e) => setConfirm(e.target.value)}
                      placeholder={t('auth.field.confirm_pwd_ph')}
                      className="h-full w-full bg-transparent text-[15px] text-ink outline-none placeholder:text-ink-mute"
                    />
                  </Field>
                </div>

                <p className="mt-3.5 min-h-[18px] text-[13px] text-crit">{error}</p>
                <SubmitButton
                  loading={loading}
                  loadingText={t('auth.submitting')}
                  text={t('auth.apply_submit')}
                />
              </form>
            )}

            {/* 登录 / 申请切换 */}
            {!applied && (
              <p className="mt-5 text-center text-[13.5px] text-ink-3">
                {mode === 'login' ? t('auth.no_account') : t('auth.have_account')}
                <button
                  type="button"
                  onClick={() => switchMode(mode === 'login' ? 'apply' : 'login')}
                  className="focus-ring ml-1 rounded font-semibold text-accent-ink transition-colors hover:text-accent-hover"
                >
                  {mode === 'login' ? t('auth.apply_account') : t('auth.back_to_login')}
                </button>
              </p>
            )}
          </div>
        </div>
      </div>

      {/* 右:空展示区(背景图透出) */}
      <div className="hidden flex-1 md:block" />
    </div>
  )
}
