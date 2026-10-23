export function formatBytes(n) {
  if (n === null || n === undefined) return '-'
  if (n < 1024) return `${n} B`
  const units = ['KB', 'MB', 'GB', 'TB', 'PB']
  let v = n
  let i = -1
  do {
    v /= 1024
    i++
  } while (v >= 1024 && i < units.length - 1)
  return `${v.toFixed(v >= 100 ? 0 : 2)} ${units[i]}`
}

export function formatDuration(ms) {
  if (ms === null || ms === undefined) return '-'
  if (ms < 1000) return `${ms} ms`
  const s = Math.floor(ms / 1000)
  if (s < 60) return `${s} s`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m} 分 ${s % 60} 秒`
  const h = Math.floor(m / 60)
  return `${h} 时 ${m % 60} 分`
}

export function formatSpeed(kbps) {
  if (!kbps) return '不限'
  return formatBytes(kbps * 1024) + '/s'
}

export function formatTime(t) {
  if (!t) return '-'
  return String(t).replace('T', ' ').replace(/Z|\+08:00$/, '')
}

export function parseListJSON(s) {
  if (!s) return []
  try {
    const arr = JSON.parse(s)
    return Array.isArray(arr) ? arr : []
  } catch (e) {
    return []
  }
}
