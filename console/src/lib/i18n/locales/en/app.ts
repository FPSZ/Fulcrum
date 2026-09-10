import type { MessageKey } from '../../index'

// app — application shell (top bar / sidebar / drawer / footer / placeholder).
export const app: Partial<Record<MessageKey, string>> = {
  // Footer
  'app.footer.tagline': 'Agent Security Platform for government and enterprise',
  'app.footer.contact': 't. Agent calls · real-time control · full-chain audit',
  'app.footer.nav': 'Navigation',
  'app.footer.nav.overview': 'Overview',
  'app.footer.nav.events': 'Events',
  'app.footer.nav.users': 'Users',
  'app.footer.nav.settings': 'Settings',
  'app.footer.legal.privacy': 'Privacy Policy',
  'app.footer.legal.terms': 'Terms of Service',
  'app.footer.legal.compliance': 'Compliance',
  'app.footer.legal.license': 'Open-Source Licenses',
  'app.footer.rights': '© 2026 Fulcrum · All rights reserved',
  'app.footer.back_to_top': 'Back to top',
  'app.footer.email': 'Email',

  // Top bar
  'app.topbar.menu': 'Open menu',
  'app.topbar.expand_sidebar': 'Expand sidebar',
  'app.topbar.collapse_sidebar': 'Collapse sidebar',
  'app.topbar.search': 'Search',
  'app.topbar.search_placeholder': 'Search events / sessions / trace_id…',
  'app.topbar.switch_bg': 'Switch background · {name}',
  'app.topbar.help': 'Help',
  'app.topbar.alerts': 'Alerts',

  // Drawer
  'app.drawer.close': 'Close menu',

  // Sidebar
  'app.sidebar.signed_out': 'Not signed in',
  'app.sidebar.logout': 'Sign out',
  // Nav groups (key is the lib/module internal group value)
  'app.sidebar.group.监测': 'Monitoring',
  'app.sidebar.group.管控': 'Control',
  'app.sidebar.group.取证': 'Forensics',
  'app.sidebar.group.系统': 'System',

  // Placeholder / shell
  'app.shell.console': 'Console',
  'app.placeholder.title': '{title} · Coming soon',
  'app.placeholder.hint': 'This module will be available in a future release',

  // Navigation (feature page labels, matching labelKey in module.tsx)
  'app.nav.overview': 'Security Overview',
  'app.nav.gateway': 'Gateway Sandbox',
  'app.nav.events': 'Live Events',
  'app.nav.assistant': 'Operations Assistant',
  'app.nav.policies': 'Policy Center',
  'app.nav.tools': 'Tool Gateway',
  'app.nav.supply': 'Supply Chain',
  'app.nav.audit': 'Audit Trail',
  'app.nav.eval': 'Evaluation',
  'app.nav.members': 'Org & Members',
  'app.nav.settings': 'Settings',
}
