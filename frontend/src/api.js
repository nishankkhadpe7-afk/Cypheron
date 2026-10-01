// All backend calls live here. With the Vite proxy (dev) or when FastAPI serves
// the built app, API_BASE is empty and requests go to the same origin.
const API_BASE = (import.meta.env.VITE_API_URL || '').replace(/\/$/, '')

function wsUrl(path) {
  if (API_BASE) return API_BASE.replace(/^http/, 'ws') + path
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${proto}//${window.location.host}${path}`
}

async function request(path, options) {
  let res
  try {
    res = await fetch(API_BASE + path, options)
  } catch {
    throw new Error('Cannot reach the Cypheron backend. Start it with: uvicorn main:app --port 8000')
  }
  const body = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(body.detail || `Request failed (${res.status})`)
  return body
}

export const getHealth = () => request('/api/health')
export const getHistory = () => request('/api/scans?limit=15')
export const getScan = (id) => request(`/api/scans/${id}`)

/**
 * Run a scan over WebSocket and stream progress.
 * onEvent receives: start, check_start, check_done, check_error.
 * Resolves with the final report; rejects with an Error.
 */
export function streamScan({ url, activeChecks, consent }, onEvent) {
  return new Promise((resolve, reject) => {
    let settled = false
    const ws = new WebSocket(wsUrl('/api/ws/scan'))
    ws.onopen = () => ws.send(JSON.stringify({ url, active_checks: activeChecks, consent }))
    ws.onmessage = (msg) => {
      const evt = JSON.parse(msg.data)
      if (evt.type === 'complete') { settled = true; resolve(evt.report) }
      else if (evt.type === 'error') { settled = true; reject(new Error(evt.error)) }
      else onEvent(evt)
    }
    ws.onerror = () => {
      if (!settled) { settled = true; reject(new Error('Cannot reach the Cypheron backend. Start it with: uvicorn main:app --port 8000')) }
    }
    ws.onclose = () => {
      if (!settled) { settled = true; reject(new Error('The connection closed before the scan finished.')) }
    }
  })
}
