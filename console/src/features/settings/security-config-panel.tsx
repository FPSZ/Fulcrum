import { useEffect, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Loader2 } from 'lucide-react'
import { Badge, Button, Input, Segmented, SettingRow, SettingSection, Switch, toast } from '@/components/ui'
import { useAuth } from '@/lib/auth'
import { type DetectorZone, getSecurityConfig, saveSecurityConfig, type SecurityConfig, type SecurityConfigWrite, type SecurityProfile } from '@/lib/admin'
import { useTranslation } from '@/lib/i18n'

const KEY = ['security-config'] as const

const ZONES: { id: DetectorZone; labelKey: 'settings.security.zone.input' | 'settings.security.zone.output' | 'settings.security.zone.tool_return' | 'settings.security.zone.assistant' }[] = [
  { id: 'gateway_input', labelKey: 'settings.security.zone.input' },
  { id: 'gateway_output', labelKey: 'settings.security.zone.output' },
  { id: 'tool_return', labelKey: 'settings.security.zone.tool_return' },
  { id: 'assistant_intent', labelKey: 'settings.security.zone.assistant' },
]

type Draft = SecurityConfig & { judge_api_key: string | null }

function toDraft(config: SecurityConfig): Draft {
  return { ...config, judge_api_key: null }
}

function toWrite(draft: Draft): SecurityConfigWrite {
  return {
    profile: draft.profile,
    zone_overrides: draft.detector_zones,
    judge_endpoint: draft.judge_endpoint,
    judge_model: draft.judge_model,
    judge_api_key: draft.judge_api_key,
    judge_timeout_seconds: draft.judge_timeout_seconds,
  }
}

export function SecurityConfigPanel() {
  const { t } = useTranslation()
  const canManage = useAuth().has('settings.manage')
  const queryClient = useQueryClient()
  const { data, isLoading, isError } = useQuery<SecurityConfig>({ queryKey: KEY, queryFn: getSecurityConfig })
  const [draft, setDraft] = useState<Draft | null>(null)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (data) setDraft(toDraft(data))
  }, [data])

  const save = async (body: SecurityConfigWrite) => {
    setSaving(true)
    try {
      const next = await saveSecurityConfig(body)
      queryClient.setQueryData(KEY, next)
      setDraft(toDraft(next))
      toast.success(t('settings.security.saved'))
    } catch (error) {
      toast.error((error as Error).message)
    } finally {
      setSaving(false)
    }
  }

  if (isLoading || !draft) {
    return (
      <SettingSection title={t('settings.security.title')}>
        <SettingRow label={t('settings.loading')}><Loader2 className="h-4 w-4 animate-spin text-ink-3" /></SettingRow>
      </SettingSection>
    )
  }
  if (isError) {
    return <SettingSection title={t('settings.security.title')}><p className="text-[14px] text-danger">{t('settings.security.load_failed')}</p></SettingSection>
  }

  const updateZone = (zone: DetectorZone, detector: string, enabled: boolean) => {
    setDraft((current) => {
      if (!current) return current
      const names = current.detector_zones[zone]
      const next = enabled ? [...names, detector] : names.filter((name) => name !== detector)
      return { ...current, detector_zones: { ...current.detector_zones, [zone]: next } }
    })
  }

  const profileItems = [
    { value: 'lightweight', label: t('settings.security.profile.lightweight') },
    { value: 'standard', label: t('settings.security.profile.standard') },
    { value: 'strict', label: t('settings.security.profile.strict') },
    { value: 'air_gapped', label: t('settings.security.profile.air_gapped') },
  ]

  return (
    <div className="space-y-5">
      <SettingSection title={t('settings.security.title')} desc={t('settings.security.desc')}>
        <SettingRow label={t('settings.security.profile.label')} hint={t('settings.security.profile.hint')}>
          <Segmented
            value={draft.profile}
            onValueChange={(value) => save({ ...toWrite(draft), profile: value as SecurityProfile, zone_overrides: {} })}
            items={profileItems}
            className="max-w-full overflow-x-auto"
          />
        </SettingRow>
        <SettingRow label={t('settings.security.status')}>
          <Badge tone="ok">{t('settings.security.active')}</Badge>
        </SettingRow>
      </SettingSection>

      <SettingSection title={t('settings.security.zones.title')} desc={t('settings.security.zones.desc')}>
        <div className="divide-y divide-line border-y border-line">
          {ZONES.map((zone) => (
            <div key={zone.id} className="py-4 first:pt-0 last:pb-0">
              <div className="mb-3 text-[14px] font-semibold text-ink">{t(zone.labelKey)}</div>
              <div className="grid gap-x-6 gap-y-2 sm:grid-cols-2">
                {draft.available_detectors.map((detector) => (
                  <label key={detector} className="flex min-h-8 items-center justify-between gap-3 text-[14px] text-ink-2">
                    <code className="min-w-0 break-all font-data text-[13px]">{detector}</code>
                    <Switch
                      checked={draft.detector_zones[zone.id].includes(detector)}
                      onCheckedChange={(checked) => updateZone(zone.id, detector, checked)}
                      disabled={!canManage || saving}
                      aria-label={`${t(zone.labelKey)} ${detector}`}
                    />
                  </label>
                ))}
              </div>
            </div>
          ))}
        </div>
      </SettingSection>

      <SettingSection title={t('settings.security.judge.title')} desc={t('settings.security.judge.desc')}>
        <SettingRow label={t('settings.security.judge.endpoint')}>
          <Input value={draft.judge_endpoint} onChange={(event) => setDraft({ ...draft, judge_endpoint: event.target.value })} disabled={!canManage || saving} className="w-full" />
        </SettingRow>
        <SettingRow label={t('settings.security.judge.model')}>
          <Input value={draft.judge_model} onChange={(event) => setDraft({ ...draft, judge_model: event.target.value })} disabled={!canManage || saving} className="w-full" />
        </SettingRow>
        <SettingRow label={t('settings.security.judge.key')} hint={draft.judge_api_key_set ? t('settings.security.judge.key_set', { masked: draft.judge_api_key_masked }) : t('settings.security.judge.key_unset')}>
          <Input type="password" value={draft.judge_api_key ?? ''} onChange={(event) => setDraft({ ...draft, judge_api_key: event.target.value })} disabled={!canManage || saving} className="w-full" />
        </SettingRow>
        <SettingRow label={t('settings.security.judge.timeout')}>
          <Input type="number" min="1" max="120" value={String(draft.judge_timeout_seconds)} onChange={(event) => setDraft({ ...draft, judge_timeout_seconds: Number(event.target.value) || 1 })} disabled={!canManage || saving} className="w-28" />
        </SettingRow>
        <SettingRow label={t('settings.security.save.label')} hint={canManage ? t('settings.security.save.hint') : t('settings.save.ro')}>
          <Button size="sm" variant="primary" onClick={() => save(toWrite(draft))} disabled={!canManage || saving}>
            {saving && <Loader2 className="h-3.5 w-3.5 animate-spin" />}{t('common.save')}
          </Button>
        </SettingRow>
      </SettingSection>
    </div>
  )
}
