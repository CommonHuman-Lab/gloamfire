import { useEffect, useState, useCallback } from 'react'
import { Activity, Server, Shield, Zap, Play, Square, ExternalLink, X, RotateCcw, AlertTriangle } from 'lucide-react'
import { api, type LabStatus, type ResultsResponse, type Container, type MitreTechnique } from '../../api/client'
import { StatCard } from '../../components/StatCard'
import { EventModal } from '../../components/EventModal'
import { TechniqueModal } from '../../components/TechniqueModal'
import type { ResultEvent } from '../../api/client'

function ResetConfirmModal({ onConfirm, onClose }: { onConfirm: () => void; onClose: () => void }) {
  const onKey = useCallback((e: KeyboardEvent) => {
    if (e.key === 'Escape') onClose()
  }, [onClose])

  useEffect(() => {
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onKey])

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-box" onClick={(e) => e.stopPropagation()} style={{ maxWidth: 420 }}>
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <AlertTriangle size={18} style={{ color: 'var(--red)' }} />
            <span className="modal-title">Reset Lab Data</span>
          </div>
          <button className="modal-close" onClick={onClose}><X size={16} /></button>
        </div>
        <div className="modal-body">
          <p style={{ color: 'var(--text-dim)', fontSize: 13, margin: '0 0 20px' }}>
            This will permanently delete <strong style={{ color: 'var(--text-h)' }}>gloamfire_telemetry.jsonl</strong> and
            clear all events, results, and MITRE technique coverage from the dashboard.
            The lab containers are not affected.
          </p>
          <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
            <button className="ctrl-btn" onClick={onClose}>Cancel</button>
            <button
              className="ctrl-btn down-btn"
              onClick={() => { onConfirm(); onClose() }}
            >
              <RotateCcw size={13} /> Yes, reset
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

function ContainerModal({ container, onClose }: { container: Container; onClose: () => void }) {
  const onKey = useCallback((e: KeyboardEvent) => {
    if (e.key === 'Escape') onClose()
  }, [onClose])

  useEffect(() => {
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onKey])

  const stateColor = container.running ? 'var(--green)' : 'var(--red)'

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-box" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div className={`container-chip-dot ${container.running ? 'up' : 'down'}`} style={{ width: 10, height: 10, borderRadius: '50%', flexShrink: 0 }} />
            <span className="modal-title">{container.name}</span>
          </div>
          <button className="modal-close" onClick={onClose}><X size={16} /></button>
        </div>
        <div className="modal-body">
          <div className="modal-row">
            <span className="modal-row-label">State</span>
            <span style={{ color: stateColor, fontWeight: 600, fontSize: 13 }}>
              {container.running ? 'Running' : 'Stopped'}
            </span>
          </div>
          <div className="modal-row">
            <span className="modal-row-label">Status</span>
            <span className="modal-row-value mono">{container.status || '—'}</span>
          </div>
          <div className="modal-row">
            <span className="modal-row-label">Image</span>
            <span className="modal-row-value mono">{container.image || '—'}</span>
          </div>
          <div className="modal-row">
            <span className="modal-row-label">Ports</span>
            <span className="modal-row-value mono">{container.ports || '—'}</span>
          </div>
          <div className="modal-row">
            <span className="modal-row-label">Container ID</span>
            <span className="modal-row-value mono">{container.id || '—'}</span>
          </div>
        </div>
      </div>
    </div>
  )
}

export function DashboardPage() {
  const [status, setStatus] = useState<LabStatus | null>(null)
  const [results, setResults] = useState<ResultsResponse | null>(null)
  const [mitreDb, setMitreDb] = useState<Map<string, MitreTechnique>>(new Map())
  const [labBusy, setLabBusy] = useState(false)
  const [showReset, setShowReset] = useState(false)
  const [selectedContainer, setSelectedContainer] = useState<Container | null>(null)
  const [selectedEvent, setSelectedEvent] = useState<ResultEvent | null>(null)
  const [selectedTechnique, setSelectedTechnique] = useState<MitreTechnique | null>(null)

  const refresh = useCallback(async () => {
    const [s, r] = await Promise.all([api.getStatus(), api.getResults()])
    setStatus(s)
    setResults(r)
  }, [])

  useEffect(() => {
    void refresh()
    api.getMitre().then((techniques) => {
      setMitreDb(new Map(techniques.map((t) => [t.id, t])))
    }).catch(() => {})
  }, [refresh])

  async function labUp() {
    setLabBusy(true)
    try { await api.labUp(); await refresh() } finally { setLabBusy(false) }
  }

  async function labDown() {
    setLabBusy(true)
    try { await api.labDown(); await refresh() } finally { setLabBusy(false) }
  }

  async function labReset() {
    await api.labReset()
    await refresh()
  }

  function openTechnique(id: string) {
    const t = mitreDb.get(id)
    if (t) setSelectedTechnique(t)
    else setSelectedTechnique({ id, name: 'Unknown Technique', tactic: 'Unknown', url: `https://attack.mitre.org/techniques/${id.split('.')[0]}/` })
  }

  const scenarioCount = results?.events
    ? [...new Set(results.events.map((e) => e.scenario))].length
    : 0

  const labReady = status?.lab_ready ?? false

  return (
    <>
      <div className="stat-grid">
        <StatCard
          icon={<Server size={22} />}
          label="Containers"
          value={status ? `${status.containers_running}/${status.containers_total}` : '—'}
          sub={labReady ? 'Lab ready' : 'Lab offline'}
          accent={labReady ? 'var(--green)' : 'var(--red)'}
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
        {!labReady && (
          <button className="ctrl-btn up-btn" onClick={() => void labUp()} disabled={labBusy}>
            <Play size={13} /> Start Lab
          </button>
        )}
        {labReady && (
          <button className="ctrl-btn down-btn" onClick={() => void labDown()} disabled={labBusy}>
            <Square size={13} /> Stop Lab
          </button>
        )}
        <button className="ctrl-btn" onClick={() => setShowReset(true)} disabled={labBusy}>
          <RotateCcw size={13} /> Reset Lab
        </button>
        <a
          className="ctrl-btn"
          href="https://localhost:5601"
          target="_blank"
          rel="noreferrer"
          title="Wazuh dashboard (admin / admin)"
        >
          <ExternalLink size={13} /> Wazuh Dashboard
        </a>
      </div>

      <div className="section-header">
        <span className="section-title">Containers</span>
      </div>
      <div className="containers-grid" style={{ marginBottom: 24 }}>
        {status?.containers.length
          ? status.containers.map((c) => (
              <div
                key={c.name}
                className="container-chip"
                style={{ cursor: 'pointer' }}
                onClick={() => setSelectedContainer(c)}
                title="Click for details"
              >
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
                <button
                  key={t}
                  className="technique-pill"
                  onClick={() => openTechnique(t)}
                  title={mitreDb.get(t)?.name ?? t}
                >
                  {t}
                </button>
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
                <tr
                  key={i}
                  className="results-row-clickable"
                  onClick={() => setSelectedEvent(e)}
                  title="Click for details"
                >
                  <td style={{ fontFamily: 'var(--mono)', color: 'var(--text-h)' }}>{e.scenario}</td>
                  <td style={{ fontFamily: 'var(--mono)' }}>{e.step_id}</td>
                  <td>
                    <span className={`exit-badge ${e.exit_code === 0 ? 'ok' : 'fail'}`}>{e.exit_code}</span>
                  </td>
                  <td style={{ color: 'var(--text-dim)' }}>{e.duration_ms}ms</td>
                  <td style={{ color: 'var(--text-dim)', fontFamily: 'var(--mono)', fontSize: 11 }}>
                    {e.timestamp ? new Date(e.timestamp).toLocaleString('en-GB', { timeZone: 'UTC', hour12: false }) + ' UTC' : '—'}
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

      {showReset && (
        <ResetConfirmModal onConfirm={() => void labReset()} onClose={() => setShowReset(false)} />
      )}
      {selectedContainer && (
        <ContainerModal container={selectedContainer} onClose={() => setSelectedContainer(null)} />
      )}
      {selectedEvent && (
        <EventModal event={selectedEvent} onClose={() => setSelectedEvent(null)} />
      )}
      {selectedTechnique && (
        <TechniqueModal technique={selectedTechnique} onClose={() => setSelectedTechnique(null)} />
      )}
    </>
  )
}
