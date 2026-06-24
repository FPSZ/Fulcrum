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
import { cn } from '@/lib/utils'
import { BackupSettings } from '../backup/backup-settings'
import { GatewayUpstreamPanel } from './gateway-upstream'
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
  return (
    <SettingRow
      label="保存更改"
      hint={ro ? '只读:需「修改设置」权限' : dirty ? '有未保存的更改' : '已是最新'}
    >
      <Button size="sm" variant="primary" onClick={onSave} disabled={ro || saving || !dirty}>
        {saving && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
        保存
      </Button>
    </SettingRow>
  )
}

/** 设置面板读取中的占位行。 */
function LoadingRow() {
  return (
    <SettingRow label="读取配置中…">
      <Loader2 className="h-4 w-4 animate-spin text-ink-3" />
    </SettingRow>
  )
}

interface Cat {
  id: string
  label: string
  icon: LucideIcon
  /** global=全局设置(影响整个系统/全体成员,写操作需「修改系统设置」权限);
   *  personal=个人设置(只作用于当前账号/浏览器,人人可改,无需权限)。 */
  scope: 'global' | 'personal'
}
// 全局设置:实例元信息 → 上游接入 → 运行状态 → 关于(影响全体,写需权限)。
// 个人设置:本机偏好 → 开发者(只存本浏览器/本账号,人人可改)。
const CATS: Cat[] = [
  { id: 'instance', label: '实例信息', icon: SlidersHorizontal, scope: 'global' },
  { id: 'gateway', label: '上游接入', icon: ShieldCheck, scope: 'global' },
  { id: 'runtime', label: '运行状态', icon: ServerCog, scope: 'global' },
  { id: 'about', label: '关于', icon: Info, scope: 'global' },
  { id: 'local', label: '本机偏好', icon: DatabaseBackup, scope: 'personal' },
  { id: 'developer', label: '开发者', icon: Code2, scope: 'personal' },
]

const SCOPES: { scope: 'global' | 'personal'; label: string }[] = [
  { scope: 'global', label: '全局设置' },
  { scope: 'personal', label: '个人设置' },
]

export function SettingsPage() {
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
                    {c.label}
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
                {sc.label}
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
                    {c.label}
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
  const { form, set, dirty, saving, onSave, loading, ro } = useSettingsForm()
  return (
    <SettingSection title="实例信息">
      {loading || !form ? (
        <LoadingRow />
      ) : (
        <>
          <SettingRow label="实例名称" hint="显示在控制台标题与导出报告中">
            <Input
              value={form.instance_name}
              onChange={(e) => set('instance_name', e.target.value)}
              disabled={ro}
              className="w-full"
            />
          </SettingRow>
          <SettingRow label="部署环境">
            <Select
              value={form.environment}
              onValueChange={(v) => set('environment', v as typeof form.environment)}
              disabled={ro}
              options={[
                { value: 'prod', label: '生产' },
                { value: 'staging', label: '预发' },
                { value: 'demo', label: '隔离演示' },
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
  return (
    <GatewayUpstreamPanel />
  )
}

function RuntimePanel() {
  return (
    <div className="space-y-5">
      <ModelsPanel />
      <SettingSection title="防护链路">
        <SettingRow label="输入闸门" hint="用户请求先过 screen_input,危险请求不转发给企业智能体">
          <Badge tone="ok">已启用</Badge>
        </SettingRow>
        <SettingRow label="工具治理" hint="工具调用经归因、评分、任务链分析与 YAML 策略判定">
          <Badge tone="ok">已启用</Badge>
        </SettingRow>
        <SettingRow label="出口检测" hint="企业智能体回复经 screen_output 检测后才返回用户">
          <Badge tone="ok">已启用</Badge>
        </SettingRow>
        <SettingRow label="失败模式" hint="安全关键路径由管线 fail-closed 兜底">
          <Badge tone="accent">强制</Badge>
        </SettingRow>
        <SettingRow label="策略来源" hint="修改 data/policies/default.yml 后重启后端生效">
          <code className="font-data text-[13px] text-ink-2">data/policies/default.yml</code>
        </SettingRow>
      </SettingSection>
      <SettingSection title="审计运行态" desc="当前版本的硬事实,不提供未接运行时的留存/通知假开关。">
        <SettingRow label="hash-chain 审计" hint="管线写入防篡改事件链">
          <Badge tone="ok">已启用</Badge>
        </SettingRow>
        <SettingRow label="审计存储" hint="当前默认 audit: memory,重启后历史清零;SQLite AuditSink 是后续后端任务">
          <Badge tone="high">内存态</Badge>
        </SettingRow>
        <SettingRow label="自动通知" hint="尚未接入站内/Webhook/邮件发送器,不在设置页伪装成可配置">
          <Badge tone="neutral">未接入</Badge>
        </SettingRow>
      </SettingSection>
    </div>
  )
}

function ModelsPanel() {
  const { form, loading } = useSettingsForm()
  const m = form?.backend_model
  return (
    <SettingSection title="模型接入" desc="经 .env 注入,控制台只读。">
      {loading || !m ? (
        <LoadingRow />
      ) : (
        <>
          <SettingRow label="出站端点" hint="OpenAI 兼容 /v1(FULCRUM_MODEL_ENDPOINT)">
            <code className="font-data text-[13px] text-ink-2">{m.endpoint}</code>
          </SettingRow>
          <SettingRow label="模型名" hint="FULCRUM_MODEL_NAME">
            <code className="font-data text-[13px] text-ink-2">{m.model_name}</code>
          </SettingRow>
          <SettingRow label="API 密钥" hint="经 .env 注入,不在控制台存储 / 展示">
            <Badge tone={m.key_set ? 'ok' : 'high'}>{m.key_set ? '已配置' : '未配置'}</Badge>
          </SettingRow>
          <SettingRow label="被保护的企业智能体" hint="网关放行后转发的上游,在「安全网关 → 上游接入」配置">
            <Badge tone="neutral">见上游接入</Badge>
          </SettingRow>
        </>
      )}
    </SettingSection>
  )
}

function LocalPanel() {
  const [convShow, setConvShow] = useConversationDisplay()
  return (
    <div className="space-y-5">
      <SettingSection title="本机偏好" desc="只保存在当前浏览器,不改变后端安全策略。">
        <SettingRow label="事件对话展示" hint="实时事件详情页展示同会话对话摘要;文本已由后端脱敏">
          <Switch checked={convShow} onCheckedChange={setConvShow} />
        </SettingRow>
      </SettingSection>
      <BackupSettings />
    </div>
  )
}

function DeveloperPanel() {
  const [devMode, setDevMode] = useDevMode()
  return (
    <SettingSection title="开发者" desc="开发与演示用页面,默认隐藏。">
      <SettingRow label="开发者模式" hint="开启后侧栏显示「网关实测」「评测验证」">
        <Switch checked={devMode} onCheckedChange={setDevMode} />
      </SettingRow>
      <SettingRow label="网关实测" hint="手动发请求看网关处置与端到端链路">
        <Badge tone={devMode ? 'accent' : 'neutral'}>{devMode ? '显示' : '隐藏'}</Badge>
      </SettingRow>
      <SettingRow label="评测验证" hint="测试集 ASR/FPR/召回记分卡">
        <Badge tone={devMode ? 'accent' : 'neutral'}>{devMode ? '显示' : '隐藏'}</Badge>
      </SettingRow>
    </SettingSection>
  )
}

function AboutPanel() {
  return (
    <SettingSection title="关于">
      <SettingRow label="产品">
        <span className="text-[15px] text-ink-2">枢衡 Fulcrum · 安全控制台</span>
      </SettingRow>
      <SettingRow label="版本">
        <span className="font-data text-[14px] text-ink-2">0.5.0</span>
      </SettingRow>
      <SettingRow label="部署形态">
        <Badge tone="accent">私有化 · 单租户 · 自托管</Badge>
      </SettingRow>
      <SettingRow label="许可证">
        <span className="text-[15px] text-ink-2">内部评估版</span>
      </SettingRow>
    </SettingSection>
  )
}
