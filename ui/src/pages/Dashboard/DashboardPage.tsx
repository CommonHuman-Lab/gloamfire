import { useEffect, useState, useCallback } from 'react'
import { Activity, Server, Shield, Zap, Play, Square } from 'lucide-react'
import { api, type LabStatus, type ResultsResponse } from '../../api/client'
import { StatCard } from '../../components/StatCard'

export function DashboardPage() {
  const [status, setStatus] = useState<LabStatus | null>(null)
  const [results, setResults] = useState<ResultsResponse | null>(null)
  const [labBusy, setLabBusy] = useState(false)

  const refresh = useCallback(async () => {
    const [s, r] = await Promise.all([api.getStatus(), api.getResults()])
    setStatus(s)
    setResults(r)
  }, [])

  useEffect(() => { void refresh() }, [refresh])

  async function labUp() {
    setLabBusy(true)
    try { await api.labUp(); await refresh() } finally { setLabBusy(false) }
  }

  async function labDown() {
    setLabBusy(true)
    try { await api.labDown(); await refresh() } finally { setLabBusy(false) }
  }

  const scenarioCount = results?.events
    ? [...new Set(results.events.map((e) => e.scenario))].length
    : 0

  return (
    <>
      <div className="stat-grid">
        <StatCard
          icon={<Server size={22} />}
          label="Containers"
          value={status ? `${status.containers_running}/${status.containers_total}` : '—'}
          sub={status?.lab_ready ? 'Lab ready' : 'Lab offline'}
          accent={status?.lab_ready ? 'var(--green)' : 'var(--red)'}
        />
        <StatCard
          icon={<Activity size={22} />}
          label="Total Events"
          value={results?.total_events ?? '—'}
          sub="from telemetry"
          accent="var(--accent)"
        />
        <StatCard
          icon={<Shield size={22} />}
          label="Scenarios Run"
          value={scenarioCount}
          sub="unique scenarios"
        />
        <StatCard
          icon={<Zap size={22} />}
          label="MITRE Techniques"
          value={results?.techniques_covered.length ?? '—'}
          sub="covered"
          accent="var(--blue)"
        />
      </div>

      <div className="section-header">
        <span className="section-title">Lab Control</span>
      </div>
      <div className="lab-controls">
        <button className="ctrl-btn up-btn" onClick={() => void labUp()} disabled={labBusy}>
          <Play size={13} /> Start Lab
        </button>
        <button className="ctrl-btn down-btn" onClick={() => void labDown()} disabled={labBusy}>
          <Square size={13} /> Stop Lab
        </button>
      </div>

      <div className="section-header">
        <span className="section-title">Containers</span>
      </div>
      <div className="containers-grid" style={{ marginBottom: 24 }}>
        {status?.containers.length
          ? status.containers.map((c) => (
              <div key={c.name} className="container-chip">
                <div className={`container-chip-dot ${c.running ? 'up' : 'down'}`} />
                {c.name}
              </div>
            ))
          : <span style={{ color: 'var(--text-dim)', fontSize: 12 }}>No containers detected</span>}
      </div>

      {results && results.techniques_covered.length > 0 && (
        <>
          <div className="section-header">
            <span className="section-title">MITRE Techniques Covered</span>
          </div>
          <div className="chart-card">
            <div className="technique-pills">
              {results.techniques_covered.map((t) => (
                <span key={t} className="technique-pill">{t}</span>
              ))}
            </div>
          </div>
        </>
      )}

      <div className="section-header">
        <span className="section-title">Recent Events</span>
      </div>
      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', overflow: 'hidden' }}>
        {results?.events.length ? (
          <table className="results-table">
            <thead>
              <tr>
                <th>Scenario</th>
                <th>Step</th>
                <th>Exit</th>
                <th>Duration</th>
                <th>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {results.events.slice(0, 10).map((e, i) => (
                <tr key={i}>
                  <td style={{ fontFamily: 'var(--mono)', color: 'var(--text-h)' }}>{e.scenario}</td>
                  <td style={{ fontFamily: 'var(--mono)' }}>{e.step_id}</td>
                  <td>
                    <span className={`exit-badge ${e.exit_code === 0 ? 'ok' : 'fail'}`}>{e.exit_code}</span>
                  </td>
                  <td style={{ color: 'var(--text-dim)' }}>{e.duration_ms}ms</td>
                  <td style={{ color: 'var(--text-dim)', fontFamily: 'var(--mono)', fontSize: 11 }}>
                    {e.timestamp ? new Date(e.timestamp).toLocaleString() : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="empty-state">
            <Activity size={32} />
            <p>No events yet — run a scenario to see results here.</p>
          </div>
        )}
      </div>
    </>
  )
}
