import { useState } from 'react'
import {
  Code2,
  DatabaseBackup,
  Info,
  Loader2,
  ShieldCheck,
  SlidersHorizontal,
  ServerCog,
  type LucideIcon,
} from 'lucide-react'
import { Badge, Button, Input, Select, SettingRow, SettingSection, Switch } from '@/components/ui'
import { useConversationDisplay } from '@/lib/conversation-pref'
import { useDevMode } from '@/lib/dev-mode'
import { type MessageKey, useTranslation } from '@/lib/i18n'
import { cn } from '@/lib/utils'
import { BackupSettings } from '../backup/backup-settings'
import { GatewayUpstreamPanel } from './gateway-upstream'
import { SecurityConfigPanel } from './security-config-panel'
import { useSettingsForm } from './use-console-settings'

/** 设置面板统一保存条:仅有未保存更改且具「修改设置」权限时可点。 */
function SaveBar({
  dirty,
  saving,
  ro,
  onSave,
}: {
  dirty: boolean
  saving: boolean
  ro: boolean
  onSave: () => void
}) {
  const { t } = useTranslation()
  return (
    <SettingRow
      label={t('settings.save.label')}
      hint={ro ? t('settings.save.ro') : dirty ? t('settings.save.dirty') : t('settings.save.clean')}
    >
      <Button size="sm" variant="primary" onClick={onSave} disabled={ro || saving || !dirty}>
        {saving && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
        {t('common.save')}
      </Button>
    </SettingRow>
  )
}

/** 设置面板读取中的占位行。 */
function LoadingRow() {
  const { t } = useTranslation()
  return (
    <SettingRow label={t('settings.loading')}>
      <Loader2 className="h-4 w-4 animate-spin text-ink-3" />
    </SettingRow>
  )
}

interface Cat {
  id: string
  labelKey: MessageKey
  icon: LucideIcon
  /** global=全局设置(影响整个系统/全体成员,写操作需「修改系统设置」权限);
   *  personal=个人设置(只作用于当前账号/浏览器,人人可改,无需权限)。 */
  scope: 'global' | 'personal'
}
// 全局设置:实例元信息 → 上游接入 → 运行状态 → 关于(影响全体,写需权限)。
// 个人设置:本机偏好 → 开发者(只存本浏览器/本账号,人人可改)。
const CATS: Cat[] = [
  { id: 'instance', labelKey: 'settings.cat.instance', icon: SlidersHorizontal, scope: 'global' },
  { id: 'gateway', labelKey: 'settings.cat.gateway', icon: ShieldCheck, scope: 'global' },
  { id: 'security', labelKey: 'settings.cat.security', icon: ShieldCheck, scope: 'global' },
  { id: 'runtime', labelKey: 'settings.cat.runtime', icon: ServerCog, scope: 'global' },
  { id: 'about', labelKey: 'settings.cat.about', icon: Info, scope: 'global' },
  { id: 'local', labelKey: 'settings.cat.local', icon: DatabaseBackup, scope: 'personal' },
  { id: 'developer', labelKey: 'settings.cat.developer', icon: Code2, scope: 'personal' },
]

const SCOPES: { scope: 'global' | 'personal'; labelKey: MessageKey }[] = [
  { scope: 'global', labelKey: 'settings.scope.global' },
  { scope: 'personal', labelKey: 'settings.scope.personal' },
]

export function SettingsPage() {
  const { t } = useTranslation()
  const [cat, setCat] = useState('instance')

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex min-h-0 flex-1 flex-col min-[821px]:flex-row">
        {/* 移动端:横向滚动分类条,按「全局/个人」分两段(中间一条竖分隔) */}
        <div className="flex shrink-0 items-center gap-1.5 overflow-x-auto border-b border-line px-3 py-2 min-[821px]:hidden [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
          {SCOPES.map((sc, si) => (
            <div key={sc.scope} className="flex shrink-0 items-center gap-1.5">
              {si > 0 && <span className="mx-0.5 h-5 w-px shrink-0 bg-line" />}
              {CATS.filter((c) => c.scope === sc.scope).map((c) => {
                const Icon = c.icon
                const active = cat === c.id
                return (
                  <button
                    key={c.id}
                    type="button"
                    onClick={() => setCat(c.id)}
                    className={cn(
                      'focus-ring flex shrink-0 items-center gap-1.5 rounded-full border px-3 py-1.5 text-[14px] font-medium transition-colors',
                      active
                        ? 'border-accent/30 bg-accent/10 text-accent-ink'
                        : 'border-line-2 text-ink-2 hover:bg-surface-2',
                    )}
                  >
                    <Icon
                      className={cn('h-4 w-4 shrink-0', active ? 'text-accent' : 'text-ink-3')}
                      strokeWidth={1.8}
                    />
                    {t(c.labelKey)}
                  </button>
                )
              })}
            </div>
          ))}
        </div>

        {/* 桌面:纵向二级导航,按「全局设置 / 个人设置」分组,各带标题 */}
        <nav className="w-56 shrink-0 space-y-3 overflow-y-auto border-r border-line p-2 max-[820px]:hidden">
          {SCOPES.map((sc) => (
            <div key={sc.scope}>
              <div className="px-2.5 pb-1 pt-1 text-[12px] font-semibold uppercase tracking-wide text-ink-mute">
                {t(sc.labelKey)}
              </div>
              {CATS.filter((c) => c.scope === sc.scope).map((c) => {
                const Icon = c.icon
                const active = cat === c.id
                return (
                  <button
                    key={c.id}
                    type="button"
                    onClick={() => setCat(c.id)}
                    className={cn(
                      'focus-ring flex w-full items-center gap-2.5 rounded-sm px-2.5 py-1.5 text-[15px] font-normal text-ink-2 transition-colors hover:bg-surface-2',
                      active && 'bg-accent/10 font-semibold text-accent-ink',
                    )}
                  >
                    <Icon
                      className={cn('h-4 w-4 shrink-0', active ? 'text-accent' : 'text-ink-3')}
                      strokeWidth={1.8}
                    />
                    {t(c.labelKey)}
                  </button>
                )
              })}
            </div>
          ))}
        </nav>

        {/* 内容 */}
        <div className="min-w-0 flex-1 overflow-y-auto px-4 py-5 md:px-8 md:py-6">
          <div className="mx-auto w-full max-w-[880px]">
            {cat === 'instance' && <InstancePanel />}
            {cat === 'gateway' && <GatewayPanel />}
            {cat === 'security' && <SecurityConfigPanel />}
            {cat === 'runtime' && <RuntimePanel />}
            {cat === 'local' && <LocalPanel />}
            {cat === 'developer' && <DeveloperPanel />}
            {cat === 'about' && <AboutPanel />}
          </div>
        </div>
      </div>
    </div>
  )
}

/* ============================ 各分类面板 ============================ */

function InstancePanel() {
  const { t } = useTranslation()
  const { form, set, dirty, saving, onSave, loading, ro } = useSettingsForm()
  return (
    <SettingSection title={t('settings.cat.instance')}>
      {loading || !form ? (
        <LoadingRow />
      ) : (
        <>
          <SettingRow label={t('settings.instance.name')} hint={t('settings.instance.name_hint')}>
            <Input
              value={form.instance_name}
              onChange={(e) => set('instance_name', e.target.value)}
              disabled={ro}
              className="w-full"
            />
          </SettingRow>
          <SettingRow label={t('settings.instance.env')}>
            <Select
              value={form.environment}
              onValueChange={(v) => set('environment', v as typeof form.environment)}
              disabled={ro}
              options={[
                { value: 'prod', label: t('settings.env.prod') },
                { value: 'staging', label: t('settings.env.staging') },
                { value: 'demo', label: t('settings.env.demo') },
              ]}
            />
          </SettingRow>
          <SaveBar dirty={dirty} saving={saving} ro={ro} onSave={onSave} />
        </>
      )}
    </SettingSection>
  )
}

function GatewayPanel() {
  return <GatewayUpstreamPanel />
}

function RuntimePanel() {
  const { t } = useTranslation()
  return (
    <div className="space-y-5">
      <ModelsPanel />
      <SettingSection title={t('settings.runtime.chain')}>
        <SettingRow label={t('settings.runtime.input')} hint={t('settings.runtime.input_hint')}>
          <Badge tone="ok">{t('settings.enabled')}</Badge>
        </SettingRow>
        <SettingRow label={t('settings.runtime.tool')} hint={t('settings.runtime.tool_hint')}>
          <Badge tone="ok">{t('settings.enabled')}</Badge>
        </SettingRow>
        <SettingRow label={t('settings.runtime.output')} hint={t('settings.runtime.output_hint')}>
          <Badge tone="ok">{t('settings.enabled')}</Badge>
        </SettingRow>
        <SettingRow
          label={t('settings.runtime.failmode')}
          hint={t('settings.runtime.failmode_hint')}
        >
          <Badge tone="accent">{t('settings.enforced')}</Badge>
        </SettingRow>
      </SettingSection>
      <SettingSection title={t('settings.audit.title')}>
        <SettingRow label={t('settings.audit.chain')} hint={t('settings.audit.chain_hint')}>
          <Badge tone="ok">{t('settings.enabled')}</Badge>
        </SettingRow>
        <SettingRow label={t('settings.audit.store')} hint={t('settings.audit.store_hint')}>
          <Badge tone="high">{t('settings.audit.store_badge')}</Badge>
        </SettingRow>
        <SettingRow label={t('settings.audit.notify')}>
          <Badge tone="neutral">{t('settings.notimpl')}</Badge>
        </SettingRow>
      </SettingSection>
    </div>
  )
}

function ModelsPanel() {
  const { t } = useTranslation()
  const { form, loading } = useSettingsForm()
  const m = form?.backend_model
  return (
    <SettingSection title={t('settings.models.title')} desc={t('settings.models.desc')}>
      {loading || !m ? (
        <LoadingRow />
      ) : (
        <>
          <SettingRow label={t('settings.models.endpoint')} hint={t('settings.models.endpoint_hint')}>
            <code className="font-data text-[13px] text-ink-2">{m.endpoint}</code>
          </SettingRow>
          <SettingRow label={t('settings.models.name')}>
            <code className="font-data text-[13px] text-ink-2">{m.model_name}</code>
          </SettingRow>
          <SettingRow label={t('settings.models.key')} hint={t('settings.models.key_hint')}>
            <Badge tone={m.key_set ? 'ok' : 'high'}>
              {m.key_set ? t('settings.configured') : t('settings.unconfigured')}
            </Badge>
          </SettingRow>
          <SettingRow
            label={t('settings.models.upstream')}
            hint={t('settings.models.upstream_hint')}
          >
            <Badge tone="neutral">{t('settings.models.upstream_badge')}</Badge>
          </SettingRow>
        </>
      )}
    </SettingSection>
  )
}

function LocalPanel() {
  const { t, locale, setLocale } = useTranslation()
  const [convShow, setConvShow] = useConversationDisplay()
  return (
    <div className="space-y-5">
      <SettingSection title={t('settings.local.title')} desc={t('settings.local.desc')}>
        <SettingRow label={t('settings.local.lang')} hint={t('settings.local.lang_hint')}>
          <Select
            value={locale}
            onValueChange={(v) => setLocale(v as 'zh' | 'en')}
            options={[
              { value: 'zh', label: '中文' },
              { value: 'en', label: 'English' },
            ]}
          />
        </SettingRow>
        <SettingRow label={t('settings.local.conv')} hint={t('settings.local.conv_hint')}>
          <Switch checked={convShow} onCheckedChange={setConvShow} />
        </SettingRow>
      </SettingSection>
      <BackupSettings />
    </div>
  )
}

function DeveloperPanel() {
  const { t } = useTranslation()
  const [devMode, setDevMode] = useDevMode()
  return (
    <SettingSection title={t('settings.dev.title')} desc={t('settings.dev.desc')}>
      <SettingRow label={t('settings.dev.mode')} hint={t('settings.dev.mode_hint')}>
        <Switch checked={devMode} onCheckedChange={setDevMode} />
      </SettingRow>
      <SettingRow label={t('settings.dev.gateway')} hint={t('settings.dev.gateway_hint')}>
        <Badge tone={devMode ? 'accent' : 'neutral'}>
          {devMode ? t('settings.shown') : t('settings.hidden')}
        </Badge>
      </SettingRow>
      <SettingRow label={t('settings.dev.eval')} hint={t('settings.dev.eval_hint')}>
        <Badge tone={devMode ? 'accent' : 'neutral'}>
          {devMode ? t('settings.shown') : t('settings.hidden')}
        </Badge>
      </SettingRow>
    </SettingSection>
  )
}

function AboutPanel() {
  const { t } = useTranslation()
  return (
    <SettingSection title={t('settings.cat.about')}>
      <SettingRow label={t('settings.about.product')}>
        <span className="text-[15px] text-ink-2">{t('settings.about.product_val')}</span>
      </SettingRow>
      <SettingRow label={t('settings.about.version')}>
        <span className="font-data text-[14px] text-ink-2">0.5.0</span>
      </SettingRow>
      <SettingRow label={t('settings.about.deploy')}>
        <Badge tone="accent">{t('settings.about.deploy_val')}</Badge>
      </SettingRow>
      <SettingRow label={t('settings.about.license')}>
        <span className="text-[15px] text-ink-2">{t('settings.about.license_val')}</span>
      </SettingRow>
    </SettingSection>
  )
}
