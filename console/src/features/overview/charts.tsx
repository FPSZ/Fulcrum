/** 总览图表:纯 SVG 矢量,低 DPI 锐利。颜色取设计令牌 CSS 变量。 */

export function BarChart({
  data,
  labels,
  highlight,
}: {
  data: number[]
  labels: string[]
  highlight: number
}) {
  const W = 640
  const H = 212
  const padL = 36
  const padT = 24
  const padB = 26
  const innerH = H - padT - padB
  const innerW = W - padL
  const max = Math.max(50, Math.ceil(Math.max(...data) / 50) * 50)
  const n = data.length
  const slot = innerW / n
  const bw = Math.min(24, slot * 0.5)

  const grid = [0, 1, 2, 3, 4].map((g) => {
    const v = (max * g) / 4
    const y = padT + innerH - (innerH * g) / 4
    return { v, y }
  })

  return (
    <svg viewBox={`0 0 ${W} ${H}`} width="100%" height={H} preserveAspectRatio="xMidYMid meet">
      {grid.map((g, i) => (
        <g key={i}>
          <line x1={padL} y1={g.y} x2={W} y2={g.y} stroke="var(--color-line)" strokeDasharray="3 5" />
          <text x={padL - 9} y={g.y + 3} textAnchor="end" fontSize="11" fill="var(--color-ink-mute)">
            {g.v}
          </text>
        </g>
      ))}
      {data.map((v, i) => {
        const x = padL + slot * i + slot / 2
        const bh = innerH * (v / max)
        const y = padT + innerH - bh
        const isHi = i === highlight
        return (
          <g key={i}>
            <rect
              x={x - bw / 2}
              y={y}
              width={bw}
              height={bh}
              rx="5"
              fill={isHi ? 'var(--color-accent)' : 'var(--color-bar-idle)'}
            />
            <text
              x={x}
              y={H - 7}
              textAnchor="middle"
              fontSize="10"
              fontWeight={isHi ? 600 : 400}
              fill={isHi ? 'var(--color-ink)' : 'var(--color-ink-mute)'}
            >
              {labels[i]}
            </text>
            {isHi && (
              <g>
                <rect x={x - 25} y={y - 32} width="50" height="23" rx="7" fill="var(--color-ink)" />
                <text x={x} y={y - 16} textAnchor="middle" fontSize="11" fontWeight={700} fill="#fff">
                  {v}
                </text>
                <path d={`M${x - 4} ${y - 9} L${x + 4} ${y - 9} L${x} ${y - 4} Z`} fill="var(--color-ink)" />
              </g>
            )}
          </g>
        )
      })}
    </svg>
  )
}

/** 秒级实时曲线:近 N 秒每秒攻击尝试,最右=当前秒(高亮),整体随秒左移 */
export function LiveChart({ data }: { data: number[] }) {
  const W = 640
  const H = 212
  const padL = 30
  const padT = 16
  const padB = 22
  const innerH = H - padT - padB
  const innerW = W - padL
  const n = data.length
  const max = Math.max(3, ...data)
  const slot = innerW / n
  const bw = Math.max(2, slot * 0.6)
  const grid = [0, 1, 2].map((g) => ({ v: Math.round((max * g) / 2), y: padT + innerH - (innerH * g) / 2 }))

  return (
    <svg viewBox={`0 0 ${W} ${H}`} width="100%" height={H} preserveAspectRatio="xMidYMid meet">
      {grid.map((g, i) => (
        <g key={i}>
          <line x1={padL} y1={g.y} x2={W} y2={g.y} stroke="var(--color-line)" strokeDasharray="3 5" />
          <text x={padL - 7} y={g.y + 3} textAnchor="end" fontSize="10" fill="var(--color-ink-mute)">
            {g.v}
          </text>
        </g>
      ))}
      {data.map((v, i) => {
        const x = padL + slot * i + slot / 2
        const bh = v > 0 ? Math.max(3, innerH * (v / max)) : 0
        const y = padT + innerH - bh
        const isNow = i === n - 1
        return (
          <rect
            key={i}
            x={x - bw / 2}
            y={y}
            width={bw}
            height={bh}
            rx="1.5"
            fill={isNow ? 'var(--color-accent)' : v > 0 ? 'var(--color-bar-idle)' : 'transparent'}
            opacity={isNow ? 1 : 0.5 + (i / n) * 0.5}
          />
        )
      })}
    </svg>
  )
}

export function Gauge({ value, label }: { value: number; label: string }) {
  const W = 220
  const H = 124
  const cx = 110
  const cy = 112
  const R = 90
  const N = 28
  const ticks = Array.from({ length: N }, (_, i) => {
    const t = (i + 0.5) / N
    const a = Math.PI - t * Math.PI
    return {
      x1: cx + Math.cos(a) * (R - 13),
      y1: cy - Math.sin(a) * (R - 13),
      x2: cx + Math.cos(a) * R,
      y2: cy - Math.sin(a) * R,
      on: t <= value / 100,
    }
  })
  return (
    <div className="relative w-full max-w-[230px]">
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" preserveAspectRatio="xMidYMid meet">
        {ticks.map((tk, i) => (
          <line
            key={i}
            x1={tk.x1}
            y1={tk.y1}
            x2={tk.x2}
            y2={tk.y2}
            strokeWidth="6"
            strokeLinecap="round"
            stroke={tk.on ? 'var(--color-accent)' : 'var(--color-bar-idle)'}
          />
        ))}
      </svg>
      <div className="absolute inset-x-0 bottom-1.5 text-center">
        <div className="tabnum text-[30px] font-bold tracking-[-0.02em] text-ink">{value}%</div>
        <div className="text-[13px] text-ink-mute">{label}</div>
      </div>
    </div>
  )
}
