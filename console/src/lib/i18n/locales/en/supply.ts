import type { MessageKey } from '../../index'

// Supply Chain page.
export const supply: Partial<Record<MessageKey, string>> = {
  'supply.empty.title': 'No component scans yet',
  'supply.empty.hint': 'Register a component inventory to have it rated by static scanning. You can also load a demo backup under "Data & backup".',

  'supply.risk_count': '{count} risks',
  'supply.rating': 'Rating: {rating}',

  'supply.col.risk': 'Risk item',
  'supply.col.severity': 'Severity',
  'supply.col.score': 'Score',
  'supply.col.detail': 'Details',

  'supply.rating.block': 'Block',
  'supply.rating.approve': 'Needs review',
  'supply.rating.sanitize': 'Sanitize',
  'supply.rating.allow': 'Allow',
}
