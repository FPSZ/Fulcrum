import { type ReactNode, useEffect, useState } from 'react'
import { motion } from 'motion/react'
import { useQueryClient } from '@tanstack/react-query'
import { Check, Loader2, Lock, Settings2, X } from 'lucide-react'
import { toast } from '@/components/ui'
import { type MessageKey, t, useTranslation } from '@/lib/i18n'
import { cn } from '@/lib/utils'
import {
  EASE,
  type ModelConfig,
  type ModelConfigUpdate,
  type ModelProtocol,
  type ModelTestResult,
} from './data'
import { saveModelConfig, testModelConfig } from './use-assistant'

// ─────────────────────────── 模型设置:配置弹窗 ───────────────────────────

// 协议元信息(表单提示)与一键预设(本地私有化优先)。name/hint 经 t() 在调用时解析当前语言。
const PROTO_META: Record<
  ModelProtocol,
  // endpointPh 多为纯 URL(无需翻译);openai 项含连接词,改走词典 key。
  { nameKey: MessageKey; hintKey: MessageKey; endpointPh?: string; endpointPhKey?: MessageKey; modelPh: string }
> = {
  openai: {
    nameKey: 'assistant.settings.proto.openai',
    hintKey: 'assistant.settings.proto.openai.hint',
    endpointPhKey: 'assistant.settings.endpoint.ph_openai',
    modelPh: 'gpt-4o-mini / deepseek-chat / qwen2.5',
  },
  ollama: {
    nameKey: 'assistant.settings.proto.ollama',
    hintKey: 'assistant.settings.proto.ollama.hint',
    endpointPh: 'http://127.0.0.1:11434',
    modelPh: 'qwen2.5 / llama3.1 / deepseek-r1',
  },
  anthropic: {
    nameKey: 'assistant.settings.proto.anthropic',
    hintKey: 'assistant.settings.proto.anthropic.hint',
    endpointPh: 'https://api.anthropic.com',
    modelPh: 'claude-3-5-sonnet-latest',
  },
}

// 预设名为产品专名(不翻译);local 标记的项渲染时追加「本地」标签(随语言切换)。
const PRESETS: {
  name: string
  local?: boolean
  protocol: ModelProtocol
  endpoint: string
  model: string
}[] = [
  {
    name: 'Ollama',
    local: true,
    protocol: 'ollama',
    endpoint: 'http://127.0.0.1:11434',
    model: 'qwen2.5',
  },
  {
    name: 'LM Studio',
    local: true,
    protocol: 'openai',
    endpoint: 'http://127.0.0.1:1234/v1',
    model: 'local-model',
  },
  { name: 'vLLM', local: true, protocol: 'openai', endpoint: 'http://127.0.0.1:8000/v1', model: '' },
  { name: 'OpenAI', protocol: 'openai', endpoint: 'https://api.openai.com/v1', model: 'gpt-4o-mini' },
  {
    name: 'DeepSeek',
    protocol: 'openai',
    endpoint: 'https://api.deepseek.com/v1',
    model: 'deepseek-chat',
  },
  {
    name: 'Anthropic',
    protocol: 'anthropic',
    endpoint: 'https://api.anthropic.com',
    model: 'claude-3-5-sonnet-latest',
  },
]

const presetLabel = (p: (typeof PRESETS)[number]): string =>
  p.local ? `${p.name} ${t('assistant.settings.preset.local')}` : p.name

export function ModelSettingsModal({
  cfg,
  canConfigure,
  onClose,
}: {
  cfg: ModelConfig | undefined
  canConfigure: boolean
  onClose: () => void
}) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [protocol, setProtocol] = useState<ModelProtocol>(cfg?.protocol ?? 'openai')
  const [endpoint, setEndpoint] = useState(cfg?.endpoint ?? '')
  const [model, setModel] = useState(cfg?.model ?? '')
  const [apiKey, setApiKey] = useState('') // 留空=保持原密钥;键入=设新值
  const [timeoutS, setTimeoutS] = useState(cfg?.timeout_seconds ?? 90)
  const [verifyTls, setVerifyTls] = useState(cfg?.verify_tls ?? true)
  const [testing, setTesting] = useState(false)
  const [result, setResult] = useState<ModelTestResult | null>(null)
  const [saving, setSaving] = useState(false)

  // Esc 关闭。
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const meta = PROTO_META[protocol]
  const ro = !canConfigure
  const valid = endpoint.trim() !== '' && model.trim() !== ''

  const payload = (): ModelConfigUpdate => ({
    protocol,
    endpoint: endpoint.trim(),
    model: model.trim(),
    api_key: apiKey ? apiKey : undefined,
    timeout_seconds: timeoutS,
    verify_tls: verifyTls,
  })

  const applyPreset = (p: (typeof PRESETS)[number]) => {
    setProtocol(p.protocol)
    setEndpoint(p.endpoint)
    setModel(p.model)
    setResult(null)
  }

  const onTest = async () => {
    setTesting(true)
    setResult(null)
    try {
      setResult(await testModelConfig(payload()))
    } catch (e) {
      setResult({ ok: false, detail: (e as Error).message })
    } finally {
      setTesting(false)
    }
  }

  const onSave = async () => {
    setSaving(true)
    try {
      await saveModelConfig(payload())
      await qc.invalidateQueries({ queryKey: ['assistant', 'model-config'] })
      toast.success(t('assistant.settings.toast.saved'), {
        description: t('assistant.settings.toast.saved_desc'),
      })
      onClose()
    } catch (e) {
      toast.error(t('assistant.settings.toast.save_failed'), { description: (e as Error).message })
    } finally {
      setSaving(false)
    }
  }

  const inputCls =
    'focus-ring h-10 w-full rounded-lg border border-line-2 bg-surface px-3 text-[14px] text-ink placeholder:text-ink-mute disabled:opacity-60'

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.18 }}
      onClick={onClose}
      className="fixed inset-0 z-50 grid place-items-center bg-ink/40 p-4 backdrop-blur-sm"
    >
      <motion.div
        initial={{ opacity: 0, scale: 0.97, y: 10 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.98, y: 6 }}
        transition={{ duration: 0.22, ease: EASE }}
        onClick={(e) => e.stopPropagation()}
        className="flex max-h-[88vh] w-full max-w-[560px] flex-col overflow-hidden rounded-2xl border border-line bg-surface shadow-xl"
      >
        <div className="flex items-center justify-between border-b border-line px-5 py-4">
          <div className="flex items-center gap-2.5">
            <div className="grid h-8 w-8 place-items-center rounded-lg bg-accent/10 text-accent">
              <Settings2 className="h-[18px] w-[18px]" />
            </div>
            <h2 className="text-[16px] font-semibold text-ink">{t('assistant.settings.title')}</h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label={t('common.close')}
            className="focus-ring grid h-8 w-8 place-items-center rounded-lg text-ink-mute transition-colors hover:bg-surface-2 hover:text-ink-2"
          >
            <X className="h-[18px] w-[18px]" />
          </button>
        </div>

        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-5 py-4">
          {ro && (
            <div className="flex items-start gap-2 rounded-lg bg-med/10 px-3 py-2.5 text-[13px] text-med">
              <Lock className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <span>{t('assistant.settings.readonly')}</span>
            </div>
          )}

          <div>
            <Label>{t('assistant.settings.protocol')}</Label>
            <div className="grid grid-cols-3 gap-2">
              {(Object.keys(PROTO_META) as ModelProtocol[]).map((p) => (
                <button
                  key={p}
                  type="button"
                  disabled={ro}
                  onClick={() => {
                    setProtocol(p)
                    setResult(null)
                  }}
                  className={cn(
                    'focus-ring rounded-lg border px-2 py-2 text-[13.5px] font-medium transition-colors disabled:opacity-60',
                    protocol === p
                      ? 'border-accent bg-accent/10 text-accent-ink'
                      : 'border-line-2 bg-surface text-ink-2 hover:border-line-3 hover:bg-surface-2',
                  )}
                >
                  {t(PROTO_META[p].nameKey)}
                </button>
              ))}
            </div>
            <p className="mt-1.5 text-[12.5px] leading-snug text-ink-mute">{t(meta.hintKey)}</p>
          </div>

          {!ro && (
            <div>
              <Label>{t('assistant.settings.preset')}</Label>
              <div className="flex flex-wrap gap-1.5">
                {PRESETS.map((p) => (
                  <button
                    key={p.name}
                    type="button"
                    onClick={() => applyPreset(p)}
                    className="focus-ring rounded-full border border-line-2 bg-surface px-2.5 py-1 text-[12.5px] text-ink-2 transition-colors hover:border-accent/40 hover:bg-accent/5 hover:text-accent-ink"
                  >
                    {presetLabel(p)}
                  </button>
                ))}
              </div>
            </div>
          )}

          <div>
            <Label>{t('assistant.settings.endpoint')}</Label>
            <input
              value={endpoint}
              disabled={ro}
              onChange={(e) => setEndpoint(e.target.value)}
              placeholder={meta.endpointPhKey ? t(meta.endpointPhKey) : meta.endpointPh}
              className={cn(inputCls, 'font-mono text-[13px]')}
            />
          </div>

          <div>
            <Label>{t('assistant.settings.model')}</Label>
            <input
              value={model}
              disabled={ro}
              onChange={(e) => setModel(e.target.value)}
              placeholder={meta.modelPh}
              className={inputCls}
            />
          </div>

          <div>
            <Label>{t('assistant.settings.api_key')}</Label>
            <input
              type="password"
              value={apiKey}
              disabled={ro}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder={
                cfg?.api_key_set
                  ? t('assistant.settings.api_key.ph_set', { masked: cfg.api_key_masked })
                  : t('assistant.settings.api_key.ph_local')
              }
              autoComplete="off"
              className={cn(inputCls, 'font-mono text-[13px]')}
            />
          </div>

          <div className="flex items-center gap-4">
            <div className="flex-1">
              <Label>{t('assistant.settings.timeout')}</Label>
              <input
                type="number"
                value={timeoutS}
                disabled={ro}
                min={1}
                max={600}
                onChange={(e) => setTimeoutS(e.target.valueAsNumber || 90)}
                className={inputCls}
              />
            </div>
            <label className="flex cursor-pointer items-center gap-2 pt-5 text-[13.5px] text-ink-2">
              <input
                type="checkbox"
                checked={verifyTls}
                disabled={ro}
                onChange={(e) => setVerifyTls(e.target.checked)}
                className="h-[16px] w-[16px] accent-accent disabled:opacity-60"
              />
              {t('assistant.settings.verify_tls')}
            </label>
          </div>

          {result && (
            <div
              className={cn(
                'flex items-start gap-2 rounded-lg px-3 py-2.5 text-[13px]',
                result.ok ? 'bg-ok/10 text-ok' : 'bg-crit/10 text-crit',
              )}
            >
              {result.ok ? (
                <Check className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              ) : (
                <X className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              )}
              <span>
                {result.detail}
                {result.ok && result.latency_ms != null ? `(${result.latency_ms} ms)` : ''}
              </span>
            </div>
          )}
        </div>

        {!ro && (
          <div className="flex items-center justify-between gap-2 border-t border-line px-5 py-3.5">
            <button
              type="button"
              onClick={onTest}
              disabled={!valid || testing}
              className="focus-ring inline-flex items-center gap-1.5 rounded-lg border border-line-2 px-3.5 py-2 text-[14px] text-ink-2 transition-colors hover:border-line-3 hover:bg-surface-2 disabled:opacity-50"
            >
              {testing && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
              {t('assistant.settings.test')}
            </button>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={onClose}
                className="focus-ring rounded-lg px-3.5 py-2 text-[14px] text-ink-3 transition-colors hover:bg-surface-2 hover:text-ink-2"
              >
                {t('common.cancel')}
              </button>
              <motion.button
                type="button"
                whileTap={{ scale: 0.96 }}
                onClick={onSave}
                disabled={!valid || saving}
                className="focus-ring inline-flex items-center gap-1.5 rounded-lg bg-accent px-4 py-2 text-[14px] font-medium text-white transition-colors hover:bg-accent-hover disabled:opacity-50"
              >
                {saving && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                {t('common.save')}
              </motion.button>
            </div>
          </div>
        )}
      </motion.div>
    </motion.div>
  )
}

function Label({ children }: { children: ReactNode }) {
  return <div className="mb-1.5 text-[13px] font-medium text-ink-2">{children}</div>
}
