import type { MessageKey } from '../../index'

// lib — user-facing messages from src/lib (requests / auth / backup).
export const lib: Partial<Record<MessageKey, string>> = {
  // Generic requests (api/client)
  'lib.api.failed': 'Operation failed',
  'lib.api.offline': 'Cannot reach the service, please try again later',
  'lib.api.bad_response': 'The service returned an unparseable response',
  'lib.api.server_error': 'Service error ({status})',

  // Sign in / account request (auth)
  'lib.auth.need_credentials': 'Please enter your account and password',
  'lib.auth.locked': 'Too many attempts — the account is temporarily locked, please try again later',
  'lib.auth.unavailable': 'Account unavailable',
  'lib.auth.invalid': 'Incorrect account or password',
  'lib.auth.login_failed': 'Sign-in failed, please try again later',
  'lib.auth.register_failed': 'Request failed, please try again later',

  // Backup import / export (backup)
  'lib.backup.too_large': 'File too large ({size} MB) — a backup should not exceed {max} MB; please check you selected the right file',
  'lib.backup.demo_missing': 'Demo backup file not found',
  'lib.backup.bad_json': 'The file is not valid JSON',
  'lib.backup.bad_file': 'Not a valid Fulcrum backup file',
  'lib.backup.unsupported_version': 'Backup version v{version} is newer than the supported v{supported}',
  'lib.backup.unknown_resource': 'Unknown resource type (not supported in this version, skipped)',
  'lib.backup.validate_failed': '{label} data validation failed',
  'lib.backup.instance': 'Fulcrum Console',
  'lib.backup.export_note': 'Manual export from the console',
}
