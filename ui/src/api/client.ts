const BASE = ''

async function get<T>(path: string): Promise<T> {
  const r = await fetch(`${BASE}${path}`)
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`)
  return r.json() as Promise<T>
}

async function post<T>(path: string, body?: unknown): Promise<T> {
  const r = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: body !== undefined ? { 'Content-Type': 'application/json' } : {},
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`)
  return r.json() as Promise<T>
}

export interface Container {
  name: string
  status: string
  running: boolean
}

export interface LabStatus {
  containers: Container[]
  lab_ready: boolean
  containers_running: number
  containers_total: number
}

export interface Scenario {
  name: string
  description: string
  severity: 'Critical' | 'High'
  mitre: string[]
  tags: string[]
}

export interface ResultEvent {
  scenario: string
  timestamp: string
  step_id: string
  exit_code: number
  mitre: string[]
  duration_ms: number
}

export interface ResultsResponse {
  events: ResultEvent[]
  total_events: number
  techniques_covered: string[]
}

export interface Chain {
  name: string
  description: string
  on_fail: string
  scenarios: string[]
}

export const api = {
  getStatus: () => get<LabStatus>('/api/status'),
  getScenarios: () => get<Scenario[]>('/api/scenarios'),
  getResults: () => get<ResultsResponse>('/api/results'),
  getChains: () => get<Chain[]>('/api/chains'),
  labUp: () => post<{ status: string }>('/api/lab/up'),
  labDown: () => post<{ status: string }>('/api/lab/down'),

  simulateStream(name: string, onEvent: (data: unknown) => void): () => void {
    const ctrl = new AbortController()
    fetch(`/api/simulate/${name}`, { method: 'POST', signal: ctrl.signal })
      .then(async (r) => {
        const reader = r.body!.getReader()
        const dec = new TextDecoder()
        let buf = ''
        while (true) {
          const { value, done } = await reader.read()
          if (done) break
          buf += dec.decode(value, { stream: true })
          const lines = buf.split('\n')
          buf = lines.pop() ?? ''
          for (const line of lines) {
            if (line.startsWith('data: ')) {
              try { onEvent(JSON.parse(line.slice(6))) } catch { /* skip */ }
            }
          }
        }
      })
      .catch(() => { /* aborted */ })
    return () => ctrl.abort()
  },
}
