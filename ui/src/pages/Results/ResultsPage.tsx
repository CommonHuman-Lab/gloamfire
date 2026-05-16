import { useEffect, useState, useCallback } from 'react'
import { RefreshCw, Database, X, CheckCircle, XCircle, Clock, Tag, Shield } from 'lucide-react'
import { api, type ResultsResponse, type ResultEvent } from '../../api/client'

function EventModal({ event, onClose }: { event: ResultEvent; onClose: () => void }) {
  const passed = event.exit_code === 0

  // close on backdrop click or Escape
  const onKey = useCallback((e: KeyboardEvent) => {
    if (e.key === 'Escape') onClose()
  }, [onClose])

  useEffect(() => {
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onKey])

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-box" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            {passed
              ? <CheckCircle size={18} style={{ color: 'var(--green)' }} />
              : <XCircle size={18} style={{ color: 'var(--red)' }} />}
            <span className="modal-title">{event.scenario}</span>
          </div>
          <button className="modal-close" onClick={onClose}><X size={16} /></button>
        </div>

        <div className="modal-body">
          <div className="modal-row">
            <span className="modal-row-label"><Tag size={12} /> Step</span>
            <span className="modal-row-value mono">{event.step_id || '—'}</span>
          </div>

          <div className="modal-row">
            <span className="modal-row-label"><Shield size={12} /> Exit code</span>
            <span className={`exit-badge ${passed ? 'ok' : 'fail'}`} style={{ fontSize: 12 }}>
              {event.exit_code}
            </span>
          </div>

          <div className="modal-row">
            <span className="modal-row-label"><Clock size={12} /> Timestamp</span>
            <span className="modal-row-value mono">
              {event.timestamp ? new Date(event.timestamp).toLocaleString() : '—'}
            </span>
          </div>

          <div className="modal-row">
            <span className="modal-row-label"><Clock size={12} /> Duration</span>
            <span className="modal-row-value">{event.duration_ms}ms</span>
          </div>

          {event.mitre.length > 0 && (
            <div className="modal-section">
              <div className="modal-section-label">MITRE ATT&amp;CK Techniques</div>
              <div className="mitre-tags" style={{ marginTop: 8 }}>
                {event.mitre.map((t) => (
                  <a
                    key={t}
                    className="mitre-tag"
                    href={`https://attack.mitre.org/techniques/${t.split('.')[0]}/`}
                    target="_blank"
                    rel="noreferrer"
                    style={{ textDecoration: 'none', cursor: 'pointer' }}
                    title={`Open ${t} on MITRE ATT&CK`}
                  >
                    {t} ↗
                  </a>
                ))}
              </div>
            </div>
          )}

          <div className="modal-section">
            <div className="modal-section-label">Raw Event</div>
            <pre className="modal-raw">{JSON.stringify(event, null, 2)}</pre>
          </div>
        </div>
      </div>
    </div>
  )
}

export function ResultsPage() {
  const [data, setData] = useState<ResultsResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [selected, setSelected] = useState<ResultEvent | null>(null)

  async function load() {
    setLoading(true)
    try { setData(await api.getResults()) } finally { setLoading(false) }
  }

  useEffect(() => { void load() }, [])

  return (
    <>
      <div className="section-header" style={{ marginBottom: 20 }}>
        <span className="section-title">Telemetry Results</span>
        <button className="ctrl-btn" onClick={() => void load()} disabled={loading} style={{ fontSize: 11 }}>
          <RefreshCw size={12} style={loading ? { animation: 'spin 1s linear infinite' } : {}} />
          Refresh
        </button>
      </div>

      {data && (
        <div className="stat-grid" style={{ marginBottom: 24 }}>
          <div className="stat-card">
            <div className="stat-icon" style={{ color: 'var(--accent)' }}><Database size={22} /></div>
            <div>
              <div className="stat-label">Total Events</div>
              <div className="stat-value">{data.total_events}</div>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-icon" style={{ color: 'var(--blue)' }}><Database size={22} /></div>
            <div>
              <div className="stat-label">Techniques Covered</div>
              <div className="stat-value">{data.techniques_covered.length}</div>
              <div className="stat-sub">{data.techniques_covered.slice(0, 3).join(', ')}{data.techniques_covered.length > 3 ? '…' : ''}</div>
            </div>
          </div>
        </div>
      )}

      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', overflow: 'hidden' }}>
        {data?.events.length ? (
          <table className="results-table">
            <thead>
              <tr>
                <th>Scenario</th>
                <th>Step</th>
                <th>Exit</th>
                <th>Duration</th>
                <th>MITRE</th>
                <th>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {data.events.map((e, i) => (
                <tr
                  key={i}
                  className="results-row-clickable"
                  onClick={() => setSelected(e)}
                  title="Click for details"
                >
                  <td style={{ fontFamily: 'var(--mono)', color: 'var(--text-h)' }}>{e.scenario}</td>
                  <td style={{ fontFamily: 'var(--mono)' }}>{e.step_id}</td>
                  <td>
                    <span className={`exit-badge ${e.exit_code === 0 ? 'ok' : 'fail'}`}>{e.exit_code}</span>
                  </td>
                  <td style={{ color: 'var(--text-dim)' }}>{e.duration_ms}ms</td>
                  <td>
                    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                      {e.mitre.map((t) => <span key={t} className="mitre-tag" style={{ fontSize: 10 }}>{t}</span>)}
                    </div>
                  </td>
                  <td style={{ color: 'var(--text-dim)', fontFamily: 'var(--mono)', fontSize: 11 }}>
                    {e.timestamp ? new Date(e.timestamp).toLocaleString() : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="empty-state">
            <Database size={32} />
            <p>No telemetry yet — run a simulation first.</p>
          </div>
        )}
      </div>

      {selected && <EventModal event={selected} onClose={() => setSelected(null)} />}

      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
      `}</style>
    </>
  )
}
