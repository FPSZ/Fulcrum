import { useEffect, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { toast } from '@/components/ui'
import { useAuth } from '@/lib/auth'
import {
  getConsoleSettings,
  saveConsoleSettings,
  type ConsoleSettings,
  type ConsoleSettingsWrite,
} from '@/lib/admin'

const KEY = ['console-settings'] as const

/** 去掉只读字段,得到 PUT 提交体。 */
export function toWrite(s: ConsoleSettings): ConsoleSettingsWrite {
  const { backend_model: _omit, ...rest } = s
  return rest
}

/**
 * 控制台通用设置(真接后端 /admin/settings)。三块面板共享一份缓存:
 * 任一面板保存都提交**全量**写体(其余字段取自服务端当前值),避免互相覆盖。
 */
export function useConsoleSettings() {
  const qc = useQueryClient()
  const query = useQuery<ConsoleSettings>({ queryKey: KEY, queryFn: getConsoleSettings })
  const save = async (body: ConsoleSettingsWrite): Promise<ConsoleSettings> => {
    const saved = await saveConsoleSettings(body)
    qc.setQueryData(KEY, saved)
    return saved
  }
  return { ...query, save }
}

/**
 * 设置面板表单态:从共享缓存初始化草稿,改字段 → 标脏 → 保存提交全量写体。
 * 三块面板各持独立草稿(均自最新服务端值起算),保存互不覆盖。
 */
export function useSettingsForm() {
  const canManage = useAuth().has('settings.manage')
  const { data, isLoading, isError, save } = useConsoleSettings()
  const [draft, setDraft] = useState<ConsoleSettings | null>(null)
  const [saving, setSaving] = useState(false)
  useEffect(() => {
    if (data) setDraft(data)
  }, [data])

  const dirty =
    !!draft && !!data && JSON.stringify(toWrite(draft)) !== JSON.stringify(toWrite(data))

  const set = <K extends keyof ConsoleSettingsWrite>(key: K, value: ConsoleSettingsWrite[K]) =>
    setDraft((d) => (d ? { ...d, [key]: value } : d))

  const onSave = async () => {
    if (!draft) return
    setSaving(true)
    try {
      await save(toWrite(draft))
      toast.success('已保存')
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setSaving(false)
    }
  }

  return { form: draft, set, dirty, saving, onSave, loading: isLoading, isError, ro: !canManage }
}
