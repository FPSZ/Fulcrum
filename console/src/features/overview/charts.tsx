/** 总览图表:纯 SVG 矢量,低 DPI 锐利。颜色取设计令牌 CSS 变量。 */

/** 柱形路径:只圆顶、底部直角(柱从基线向上生长,圆角随高度自适应不变形) */
function topRoundedBar(x: number, y: number, w: number, h: number, r: number): string {
  const rr = Math.max(0, Math.min(r, w / 2, h))
  return `M${x},${y + h} L${x},${y + rr} Q${x},${y} ${x + rr},${y} L${x + w - rr},${y} Q${x + w},${y} ${x + w},${y + rr} L${x + w},${y + h} Z`
}

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
  const bw = Math.min(26, slot * 0.56)

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
            <path
              d={topRoundedBar(x - bw / 2, y, bw, bh, 6)}
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

/** 距今 sec 秒 → 相对时间标签(横坐标用) */
function fmtAgo(sec: number): string {
  if (sec <= 0.5) return '现在'
  if (sec < 60) return `-${Math.round(sec)}秒`
  if (sec < 3600) return `-${Math.round(sec / 60)}分`
  if (sec < 86400) {
    const h = sec / 3600
    return `-${h < 10 ? +h.toFixed(1) : Math.round(h)}时`
  }
  return `-${+(sec / 86400).toFixed(1)}天`
}

/**
 * 实时滚动曲线:柱子数量/粗细随窗口自适应(窗口小→桶大→柱粗根数少),
 * 最右=当前桶(高亮),横坐标按窗口标相对时间刻度。
 */
export function LiveChart({
  data,
  windowSec,
  bucketSec,
}: {
  data: number[]
  windowSec: number
  bucketSec: number
}) {
  const W = 640
  const H = 212
  const padL = 30
  const padT = 16
  const padB = 26
  const innerH = H - padT - padB
  const innerW = W - padL
  const n = data.length
  const max = Math.max(3, ...data)
  const slot = innerW / n
  const bw = Math.min(36, slot * 0.62)
  const grid = [0, 1, 2].map((g) => ({ v: Math.round((max * g) / 2), y: padT + innerH - (innerH * g) / 2 }))
  // 横坐标 5 个刻度:从左(−window)到右(现在),按桶大小对齐成整刻度
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => {
    const stepsAgo = Math.round(((1 - f) * windowSec) / bucketSec)
    const anchor: 'start' | 'middle' | 'end' = f === 0 ? 'start' : f === 1 ? 'end' : 'middle'
    return { x: padL + f * innerW, label: fmtAgo(stepsAgo * bucketSec), anchor }
  })

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
          <path
            key={i}
            d={topRoundedBar(x - bw / 2, y, bw, bh, 3)}
            fill={isNow ? 'var(--color-accent)' : v > 0 ? 'var(--color-bar-idle)' : 'transparent'}
            opacity={isNow ? 1 : 0.55 + (i / n) * 0.45}
          />
        )
      })}
      {ticks.map((t, i) => (
        <text
          key={i}
          x={t.x}
          y={H - 8}
          textAnchor={t.anchor}
          fontSize="10"
          fill="var(--color-ink-mute)"
        >
          {t.label}
        </text>
      ))}
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
