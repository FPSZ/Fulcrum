import { useEffect, useState } from 'react'
import { CheckCircle2, Loader2, PlugZap, XCircle } from 'lucide-react'
import { Badge, Button, Input, Select, SettingRow, SettingSection, Switch, toast } from '@/components/ui'
import {
  getGatewayConfig,
  saveGatewayConfig,
  testGatewayConfig,
  type GatewayAuthType,
  type GatewayConfig,
  type GatewayConfigWrite,
  type GatewayProbeResult,
  type GatewayProtocol,
} from '@/lib/admin'
import { useAuth } from '@/lib/auth'
import { cn } from '@/lib/utils'

type Form = Omit<GatewayConfig, 'auth_value_masked' | 'auth_value_set'>

const PROTOCOLS: { value: GatewayProtocol; label: string }[] = [
  { value: 'openai', label: 'OpenAI 兼容(推荐 · 覆盖市面多数)' },
  { value: 'rest', label: '通用 REST(自研接口)' },
  { value: 'native', label: '枢衡 /chat(内置示例体)' },
]
const AUTH_TYPES: { value: GatewayAuthType; label: string }[] = [
  { value: 'none', label: '无' },
  { value: 'bearer', label: 'Bearer 令牌' },
  { value: 'header', label: '自定义 Header' },
]
const PATH_HINT: Record<GatewayProtocol, string> = {
  openai: '/chat/completions',
  rest: '/',
  native: '/chat',
}

/** 上游接入配置 —— 真实对接后端 /admin/gateway-config(读/存/测试连接)。 */
export function GatewayUpstreamPanel() {
  const canManage = useAuth().has('settings.manage')
  const [form, setForm] = useState<Form | null>(null)
  const [meta, setMeta] = useState({ set: false, masked: '' })
  const [pwd, setPwd] = useState('')
  const [pwdTouched, setPwdTouched] = useState(false)
  const [loadErr, setLoadErr] = useState('')
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState(false)
  const [probe, setProbe] = useState<GatewayProbeResult | null>(null)

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
  }, [])

  if (loadErr) {
    return (
      <SettingSection title="上游接入">
        <SettingRow label="加载失败" hint={loadErr}>
          <Badge tone="high">不可用</Badge>
        </SettingRow>
      </SettingSection>
    )
  }
  if (!form) {
    return (
      <SettingSection title="上游接入">
        <SettingRow label="读取配置中…">
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
      r.ok ? toast.success(`连接正常 · ${r.latency_ms}ms`) : toast.error(`连接失败:${r.detail}`)
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
      toast.success('已保存,立即生效(无需重启)')
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setSaving(false)
    }
  }

  const ro = !canManage
  const pwdPlaceholder = meta.set ? `已设置 ${meta.masked}(留空不改)` : '未设置'

  return (
    <SettingSection title="上游接入" desc="密钥仅存后端,不回前端。">
      <SettingRow label="启用接入" hint="关闭后只判定不转发">
        <Switch
          checked={form.enabled}
          onCheckedChange={(v) => set('enabled', v)}
          disabled={ro}
        />
      </SettingRow>

      <SettingRow label="名称">
        <Input
          value={form.name}
          onChange={(e) => set('name', e.target.value)}
          disabled={ro}
          className="w-full"
        />
      </SettingRow>

      <SettingRow label="接入协议" hint="多数智能体 / LLM 网关为 OpenAI 兼容">
        <Select
          value={form.protocol}
          onValueChange={(v) => set('protocol', v as GatewayProtocol)}
          options={PROTOCOLS}
          disabled={ro}
          className="w-full"
        />
      </SettingRow>

      <SettingRow label="上游地址" hint="企业智能体基址,如 http://10.0.0.5:8000/v1">
        <Input
          value={form.endpoint}
          onChange={(e) => set('endpoint', e.target.value)}
          disabled={ro}
          placeholder="http://host:port"
          className="w-full"
        />
      </SettingRow>

      <SettingRow label="请求路径" hint={`留空按协议默认(${PATH_HINT[form.protocol]})`}>
        <Input
          value={form.path}
          onChange={(e) => set('path', e.target.value)}
          disabled={ro}
          placeholder={PATH_HINT[form.protocol]}
          className="w-full"
        />
      </SettingRow>

      {form.protocol === 'openai' && (
        <SettingRow label="模型名" hint="转发给上游的 model 字段">
          <Input
            value={form.model}
            onChange={(e) => set('model', e.target.value)}
            disabled={ro}
            placeholder="如 gpt-4o-mini / mimo-v2.5-pro"
            className="w-full"
          />
        </SettingRow>
      )}

      {form.protocol === 'rest' && (
        <>
          <SettingRow label="请求字段名" hint="把用户消息放进请求体的哪个字段">
            <Input
              value={form.rest_message_field}
              onChange={(e) => set('rest_message_field', e.target.value)}
              disabled={ro}
              className="w-full"
            />
          </SettingRow>
          <SettingRow label="响应取值路径" hint="点路径从响应取回复,如 data.answer">
            <Input
              value={form.rest_response_path}
              onChange={(e) => set('rest_response_path', e.target.value)}
              disabled={ro}
              className="w-full"
            />
          </SettingRow>
        </>
      )}

      <SettingRow label="认证方式">
        <Select
          value={form.auth_type}
          onValueChange={(v) => set('auth_type', v as GatewayAuthType)}
          options={AUTH_TYPES}
          disabled={ro}
        />
      </SettingRow>

      {form.auth_type === 'header' && (
        <SettingRow label="Header 名称">
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
        <SettingRow label="密钥 / 令牌" hint="只写不回:保存后前端只见掩码">
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

      <SettingRow label="超时(秒)">
        <Input
          type="number"
          value={String(form.timeout_seconds)}
          onChange={(e) => set('timeout_seconds', Number(e.target.value) || 0)}
          disabled={ro}
          className="w-full"
        />
      </SettingRow>

      <SettingRow label="校验 TLS 证书" hint="自签名内网证书可关闭(谨慎)">
        <Switch
          checked={form.verify_tls}
          onCheckedChange={(v) => set('verify_tls', v)}
          disabled={ro}
        />
      </SettingRow>

      {/* 操作条:测试连接 + 保存,带结果反馈 */}
      <SettingRow
        label="连接与保存"
        hint={canManage ? '先测试连通与认证,再保存生效' : '只读:需「修改设置」权限'}
      >
        <div className="flex flex-col items-end gap-2">
          <div className="flex items-center gap-2">
            <Button size="sm" onClick={onTest} disabled={ro || testing || !form.endpoint}>
              {testing ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <PlugZap className="h-3.5 w-3.5" />
              )}
              测试连接
            </Button>
            <Button
              size="sm"
              variant="primary"
              onClick={onSave}
              disabled={ro || saving || !form.endpoint}
            >
              {saving && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
              保存
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
