import { useEffect, useState, useCallback, useMemo } from 'react'
import { Play, Loader, CheckCircle, XCircle, Layers, Search, ArrowUpDown } from 'lucide-react'
import { api, type Scenario } from '../../api/client'

interface RunState {
  status: 'idle' | 'running' | 'done' | 'error'
  log: string[]
  passed?: number
  failed?: number
}

type SortKey = 'name' | 'severity'
type SortDir = 'asc' | 'desc'
type SeverityFilter = 'all' | 'Critical' | 'High'

export function ScenariosPage() {
  const [scenarios, setScenarios] = useState<Scenario[]>([])
  const [runs, setRuns] = useState<Record<string, RunState>>({})
  const [cancellers, setCancellers] = useState<Record<string, () => void>>({})
  const [query, setQuery] = useState('')
  const [sortKey, setSortKey] = useState<SortKey>('name')
  const [sortDir, setSortDir] = useState<SortDir>('asc')
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all')

  useEffect(() => { void api.getScenarios().then(setScenarios) }, [])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    let result = scenarios.filter((s) => {
      if (severityFilter !== 'all' && s.severity !== severityFilter) return false
      if (!q) return true
      return (
        s.name.toLowerCase().includes(q) ||
        s.description.toLowerCase().includes(q) ||
        s.mitre.some((t) => t.toLowerCase().includes(q)) ||
        s.tags.some((t) => t.toLowerCase().includes(q))
      )
    })
    result = [...result].sort((a, b) => {
      let cmp = 0
      if (sortKey === 'name') cmp = a.name.localeCompare(b.name)
      if (sortKey === 'severity') {
        const rank = (s: Scenario) => s.severity === 'Critical' ? 0 : 1
        cmp = rank(a) - rank(b)
      }
      return sortDir === 'asc' ? cmp : -cmp
    })
    return result
  }, [scenarios, query, sortKey, sortDir, severityFilter])

  function toggleSort(key: SortKey) {
    if (sortKey === key) setSortDir((d) => d === 'asc' ? 'desc' : 'asc')
    else { setSortKey(key); setSortDir('asc') }
  }

  const runScenario = useCallback((name: string) => {
    setRuns((prev) => ({ ...prev, [name]: { status: 'running', log: ['Starting…'] } }))

    const cancel = api.simulateStream(name, (data) => {
      const ev = data as Record<string, unknown>
      if (ev.type === 'start') {
        setRuns((prev) => ({
          ...prev,
          [name]: { ...prev[name]!, log: [`Running ${String(ev.scenario)}…`] },
        }))
      } else if (ev.type === 'done') {
        const passed = typeof ev.passed === 'number' ? ev.passed : 0
        const failed = typeof ev.failed === 'number' ? ev.failed : 0
        setRuns((prev) => ({
          ...prev,
          [name]: {
            status: failed > 0 ? 'error' : 'done',
            log: [`${passed} passed · ${failed} failed`],
            passed,
            failed,
          },
        }))
      } else if (ev.type === 'error') {
        setRuns((prev) => ({
          ...prev,
          [name]: { status: 'error', log: [String(ev.message ?? 'Unknown error')] },
        }))
      }
    })

    setCancellers((prev) => ({ ...prev, [name]: cancel }))
  }, [])

  const stopScenario = useCallback((name: string) => {
    cancellers[name]?.()
    setRuns((prev) => ({ ...prev, [name]: { status: 'idle', log: [] } }))
  }, [cancellers])

  const sortLabel = (key: SortKey) => {
    if (sortKey !== key) return <ArrowUpDown size={12} style={{ opacity: 0.4 }} />
    return <ArrowUpDown size={12} style={{ color: 'var(--accent)' }} />
  }

  return (
    <>
      <div className="section-header" style={{ marginBottom: 16 }}>
        <span className="section-title">Attack Scenarios</span>
        <span style={{ fontSize: 12, color: 'var(--text-dim)' }}>
          {filtered.length}/{scenarios.length}
        </span>
      </div>

      {/* Search + filter toolbar */}
      <div className="scenarios-toolbar">
        <div className="scenarios-search">
          <Search size={13} style={{ color: 'var(--text-dim)', flexShrink: 0 }} />
          <input
            className="scenarios-search-input"
            placeholder="Search by name, technique, tag…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          {query && (
            <button className="scenarios-clear-btn" onClick={() => setQuery('')}>×</button>
          )}
        </div>

        <div className="scenarios-filters">
          {(['all', 'Critical', 'High'] as SeverityFilter[]).map((f) => (
            <button
              key={f}
              className={`filter-btn${severityFilter === f ? ' active' : ''} ${f === 'Critical' ? 'filter-critical' : f === 'High' ? 'filter-high' : ''}`}
              onClick={() => setSeverityFilter(f)}
            >
              {f === 'all' ? 'All' : f}
            </button>
          ))}
        </div>

        <div className="scenarios-sorts">
          <button className={`sort-btn${sortKey === 'name' ? ' active' : ''}`} onClick={() => toggleSort('name')}>
            {sortLabel('name')} Name {sortKey === 'name' ? (sortDir === 'asc' ? '↑' : '↓') : ''}
          </button>
          <button className={`sort-btn${sortKey === 'severity' ? ' active' : ''}`} onClick={() => toggleSort('severity')}>
            {sortLabel('severity')} Severity {sortKey === 'severity' ? (sortDir === 'asc' ? '↑' : '↓') : ''}
          </button>
        </div>
      </div>

      {scenarios.length === 0 && (
        <div className="empty-state">
          <Layers size={32} />
          <p>No scenarios found in scenarios/ directory.</p>
        </div>
      )}

      {scenarios.length > 0 && filtered.length === 0 && (
        <div className="empty-state">
          <Search size={32} />
          <p>No scenarios match <strong>"{query}"</strong></p>
        </div>
      )}

      <div className="scenario-grid">
        {filtered.map((s) => {
          const run = runs[s.name] ?? { status: 'idle', log: [] }
          const isRunning = run.status === 'running'
          return (
            <div key={s.name} className="scenario-card">
              <div className="scenario-card-header">
                <span className="scenario-name">{s.name}</span>
                <span className={`badge ${s.severity === 'Critical' ? 'badge-critical' : 'badge-high'}`}>
                  {s.severity}
                </span>
              </div>

              {s.description && <p className="scenario-desc">{s.description}</p>}

              {s.mitre.length > 0 && (
                <div className="mitre-tags">
                  {s.mitre.map((t) => <span key={t} className="mitre-tag">{t}</span>)}
                </div>
              )}

              {run.log.length > 0 && (
                <div className="sse-output">
                  {run.log.map((line, i) => (
                    <div
                      key={i}
                      className={
                        run.status === 'done' ? 'sse-pass' :
                        run.status === 'error' ? 'sse-fail' : 'sse-running'
                      }
                    >
                      {run.status === 'done' && <CheckCircle size={10} style={{ marginRight: 4, verticalAlign: 'middle' }} />}
                      {run.status === 'error' && <XCircle size={10} style={{ marginRight: 4, verticalAlign: 'middle' }} />}
                      {line}
                    </div>
                  ))}
                </div>
              )}

              {isRunning ? (
                <button className="run-btn running" onClick={() => stopScenario(s.name)}>
                  <Loader size={12} style={{ animation: 'spin 1s linear infinite' }} />
                  Running…
                </button>
              ) : (
                <button className="run-btn" onClick={() => runScenario(s.name)}>
                  <Play size={12} />
                  Run Simulation
                </button>
              )}
            </div>
          )
        })}
      </div>

      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
      `}</style>
    </>
  )
}
