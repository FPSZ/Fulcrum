import { useEffect, useState } from 'react'
import { CheckCircle2, Loader2, PlugZap, XCircle } from 'lucide-react'
import { Badge, Button, Input, Select, SettingRow, SettingSection, Switch, toast } from '@/components/ui'
import {
  getGatewayConfig,
  listDepartments,
  saveGatewayConfig,
  testGatewayConfig,
  type Department,
  type GatewayAuthType,
  type GatewayConfig,
  type GatewayConfigWrite,
  type GatewayProbeResult,
  type GatewayProtocol,
} from '@/lib/admin'
import { useAuth } from '@/lib/auth'
import { useTranslation } from '@/lib/i18n'
import { cn } from '@/lib/utils'

type Form = Omit<GatewayConfig, 'auth_value_masked' | 'auth_value_set'>

const NO_TEAM = '0' // Select 哨兵:未归属(全局可见)

const PATH_HINT: Record<GatewayProtocol, string> = {
  openai: '/chat/completions',
  rest: '/',
  native: '/chat',
}

/** 上游接入配置 —— 真实对接后端 /admin/gateway-config(读/存/测试连接)。 */
export function GatewayUpstreamPanel() {
  const { t } = useTranslation()
  const canManage = useAuth().has('settings.manage')
  const PROTOCOLS: { value: GatewayProtocol; label: string }[] = [
    { value: 'openai', label: t('settings.up.proto.openai') },
    { value: 'rest', label: t('settings.up.proto.rest') },
    { value: 'native', label: t('settings.up.proto.native') },
  ]
  const AUTH_TYPES: { value: GatewayAuthType; label: string }[] = [
    { value: 'none', label: t('settings.up.auth.none') },
    { value: 'bearer', label: t('settings.up.auth.bearer') },
    { value: 'header', label: t('settings.up.auth.header') },
  ]
  const [form, setForm] = useState<Form | null>(null)
  const [meta, setMeta] = useState({ set: false, masked: '' })
  const [pwd, setPwd] = useState('')
  const [pwdTouched, setPwdTouched] = useState(false)
  const [loadErr, setLoadErr] = useState('')
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState(false)
  const [probe, setProbe] = useState<GatewayProbeResult | null>(null)
  const [teams, setTeams] = useState<Department[]>([])

  const apply = (c: GatewayConfig) => {
    const { auth_value_masked, auth_value_set, ...rest } = c
    setForm(rest)
    setMeta({ set: auth_value_set, masked: auth_value_masked })
    setPwd('')
    setPwdTouched(false)
  }

  useEffect(() => {
    getGatewayConfig()
      .then(apply)
      .catch((e: Error) => setLoadErr(e.message))
    listDepartments()
      .then(setTeams)
      .catch(() => setTeams([])) // 团队列表仅用于归属选择,取不到不阻断主表单
  }, [])

  if (loadErr) {
    return (
      <SettingSection title={t('settings.up.title')}>
        <SettingRow label={t('settings.up.load_failed')} hint={loadErr}>
          <Badge tone="high">{t('settings.up.unavailable')}</Badge>
        </SettingRow>
      </SettingSection>
    )
  }
  if (!form) {
    return (
      <SettingSection title={t('settings.up.title')}>
        <SettingRow label={t('settings.up.loading')}>
          <Loader2 className="h-4 w-4 animate-spin text-ink-3" />
        </SettingRow>
      </SettingSection>
    )
  }

  const set = <K extends keyof Form>(key: K, value: Form[K]) => {
    setForm((f) => (f ? { ...f, [key]: value } : f))
    setProbe(null)
  }
  const buildWrite = (): GatewayConfigWrite => ({
    ...form,
    auth_value: pwdTouched ? pwd : null,
  })

  const onTest = async () => {
    setTesting(true)
    setProbe(null)
    try {
      const r = await testGatewayConfig(buildWrite())
      setProbe(r)
      r.ok
        ? toast.success(t('settings.up.test_ok', { ms: r.latency_ms }))
        : toast.error(t('settings.up.test_fail', { detail: r.detail }))
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setTesting(false)
    }
  }
  const onSave = async () => {
    setSaving(true)
    try {
      const saved = await saveGatewayConfig(buildWrite())
      apply(saved)
      toast.success(t('settings.up.saved'))
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setSaving(false)
    }
  }

  const ro = !canManage
  const pwdPlaceholder = meta.set
    ? t('settings.up.secret_set', { masked: meta.masked })
    : t('settings.up.secret_unset')

  return (
    <SettingSection title={t('settings.up.title')} desc={t('settings.up.desc')}>
      <SettingRow label={t('settings.up.enable')} hint={t('settings.up.enable_hint')}>
        <Switch
          checked={form.enabled}
          onCheckedChange={(v) => set('enabled', v)}
          disabled={ro}
        />
      </SettingRow>

      <SettingRow label={t('settings.up.name')}>
        <Input
          value={form.name}
          onChange={(e) => set('name', e.target.value)}
          disabled={ro}
          className="w-full"
        />
      </SettingRow>

      <SettingRow label={t('settings.up.team')} hint={t('settings.up.team_hint')}>
        <Select
          value={form.team_id == null ? NO_TEAM : String(form.team_id)}
          onValueChange={(v) => set('team_id', v === NO_TEAM ? null : Number(v))}
          options={[
            { value: NO_TEAM, label: t('settings.up.team_none') },
            ...teams.map((tm) => ({ value: String(tm.id), label: tm.name })),
          ]}
          disabled={ro}
          className="w-full"
        />
      </SettingRow>

      <SettingRow label={t('settings.up.protocol')} hint={t('settings.up.protocol_hint')}>
        <Select
          value={form.protocol}
          onValueChange={(v) => set('protocol', v as GatewayProtocol)}
          options={PROTOCOLS}
          disabled={ro}
          className="w-full"
        />
      </SettingRow>

      <SettingRow label={t('settings.up.endpoint')} hint={t('settings.up.endpoint_hint')}>
        <Input
          value={form.endpoint}
          onChange={(e) => set('endpoint', e.target.value)}
          disabled={ro}
          placeholder="http://host:port"
          className="w-full"
        />
      </SettingRow>

      <SettingRow
        label={t('settings.up.path')}
        hint={t('settings.up.path_hint', { default: PATH_HINT[form.protocol] })}
      >
        <Input
          value={form.path}
          onChange={(e) => set('path', e.target.value)}
          disabled={ro}
          placeholder={PATH_HINT[form.protocol]}
          className="w-full"
        />
      </SettingRow>

      {form.protocol === 'openai' && (
        <SettingRow label={t('settings.up.model')} hint={t('settings.up.model_hint')}>
          <Input
            value={form.model}
            onChange={(e) => set('model', e.target.value)}
            disabled={ro}
            placeholder="gpt-4o-mini / mimo-v2.5-pro"
            className="w-full"
          />
        </SettingRow>
      )}

      {form.protocol === 'rest' && (
        <>
          <SettingRow label={t('settings.up.rest_field')} hint={t('settings.up.rest_field_hint')}>
            <Input
              value={form.rest_message_field}
              onChange={(e) => set('rest_message_field', e.target.value)}
              disabled={ro}
              className="w-full"
            />
          </SettingRow>
          <SettingRow label={t('settings.up.rest_path')} hint={t('settings.up.rest_path_hint')}>
            <Input
              value={form.rest_response_path}
              onChange={(e) => set('rest_response_path', e.target.value)}
              disabled={ro}
              className="w-full"
            />
          </SettingRow>
        </>
      )}

      <SettingRow label={t('settings.up.auth_type')}>
        <Select
          value={form.auth_type}
          onValueChange={(v) => set('auth_type', v as GatewayAuthType)}
          options={AUTH_TYPES}
          disabled={ro}
        />
      </SettingRow>

      {form.auth_type === 'header' && (
        <SettingRow label={t('settings.up.header_name')}>
          <Input
            value={form.auth_header}
            onChange={(e) => set('auth_header', e.target.value)}
            disabled={ro}
            placeholder="X-Api-Key"
            className="w-full"
          />
        </SettingRow>
      )}

      {form.auth_type !== 'none' && (
        <SettingRow label={t('settings.up.secret')} hint={t('settings.up.secret_hint')}>
          <Input
            type="password"
            value={pwd}
            onChange={(e) => {
              setPwd(e.target.value)
              setPwdTouched(true)
              setProbe(null)
            }}
            disabled={ro}
            placeholder={pwdPlaceholder}
            className="w-full"
          />
        </SettingRow>
      )}

      <SettingRow label={t('settings.up.timeout')}>
        <Input
          type="number"
          value={String(form.timeout_seconds)}
          onChange={(e) => set('timeout_seconds', Number(e.target.value) || 0)}
          disabled={ro}
          className="w-full"
        />
      </SettingRow>

      <SettingRow label={t('settings.up.verify_tls')} hint={t('settings.up.verify_tls_hint')}>
        <Switch
          checked={form.verify_tls}
          onCheckedChange={(v) => set('verify_tls', v)}
          disabled={ro}
        />
      </SettingRow>

      {/* 操作条:测试连接 + 保存,带结果反馈 */}
      <SettingRow
        label={t('settings.up.action')}
        hint={canManage ? t('settings.up.action_hint') : t('settings.up.action_ro')}
      >
        <div className="flex flex-col items-end gap-2">
          <div className="flex items-center gap-2">
            <Button size="sm" onClick={onTest} disabled={ro || testing || !form.endpoint}>
              {testing ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <PlugZap className="h-3.5 w-3.5" />
              )}
              {t('settings.up.test')}
            </Button>
            <Button
              size="sm"
              variant="primary"
              onClick={onSave}
              disabled={ro || saving || !form.endpoint}
            >
              {saving && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
              {t('common.save')}
            </Button>
          </div>
          {probe && (
            <span
              className={cn(
                'flex items-center gap-1.5 text-[13px]',
                probe.ok ? 'text-emerald-600' : 'text-crit',
              )}
            >
              {probe.ok ? (
                <CheckCircle2 className="h-3.5 w-3.5" />
              ) : (
                <XCircle className="h-3.5 w-3.5" />
              )}
              {probe.detail} · {probe.latency_ms}ms
              {probe.status_code != null && ` · HTTP ${probe.status_code}`}
            </span>
          )}
        </div>
      </SettingRow>
    </SettingSection>
  )
}
