// lib —— src/lib 面向用户的提示(请求 / 鉴权 / 备份)。
export const lib = {
  // 通用请求(api/client)
  'lib.api.failed': '操作失败',
  'lib.api.offline': '无法连接服务,请稍后再试',
  'lib.api.bad_response': '服务返回了无法解析的响应',
  'lib.api.server_error': '服务异常({status})',

  // 登录 / 申请账号(auth)
  'lib.auth.need_credentials': '请输入账号和口令',
  'lib.auth.locked': '尝试过于频繁,账号已被临时锁定,请稍后再试',
  'lib.auth.unavailable': '账号不可用',
  'lib.auth.invalid': '账号或口令错误',
  'lib.auth.login_failed': '登录失败,请稍后再试',
  'lib.auth.register_failed': '申请失败,请稍后再试',

  // 备份导入 / 导出(backup)
  'lib.backup.too_large': '文件过大({size} MB),备份不应超过 {max} MB,请确认选对了文件',
  'lib.backup.demo_missing': '未找到演示备份文件',
  'lib.backup.bad_json': '文件不是合法的 JSON',
  'lib.backup.bad_file': '不是有效的枢衡备份文件',
  'lib.backup.unsupported_version': '备份版本 v{version} 高于当前支持的 v{supported}',
  'lib.backup.unknown_resource': '未知资源类型(当前版本不支持,已忽略)',
  'lib.backup.validate_failed': '{label} 数据校验失败',
  'lib.backup.instance': '枢衡控制台',
  'lib.backup.export_note': '控制台手动导出',
} as const
