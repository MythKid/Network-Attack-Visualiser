/** Number, byte and confidence formatting helpers. */

export function formatInt(value: number): string {
  return value.toLocaleString('en-US')
}

export function formatBytes(value: number): string {
  if (!Number.isFinite(value)) return '—'
  if (value < 1024) return `${value} B`
  const units = ['KiB', 'MiB', 'GiB', 'TiB']
  let scaled = value / 1024
  let unit = 0
  while (scaled >= 1024 && unit < units.length - 1) {
    scaled /= 1024
    unit += 1
  }
  return `${scaled.toFixed(1)} ${units[unit]}`
}

export function formatConfidence(value: number): string {
  return `${Math.round(value * 100)}%`
}

/** "src -> dst" with a null source rendered as "any". */
export function formatFlow(srcIp: string | null, dstIp: string): string {
  return `${srcIp ?? 'any'} → ${dstIp}`
}
