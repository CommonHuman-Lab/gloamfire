import { useEffect, useCallback } from 'react'
import { X, CheckCircle, XCircle, Clock, Tag, Shield } from 'lucide-react'
import { type ResultEvent } from '../api/client'

export function EventModal({ event, onClose }: { event: ResultEvent; onClose: () => void }) {
  const passed = event.exit_code === 0

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
              {event.timestamp
                ? new Date(event.timestamp).toLocaleString('en-GB', { timeZone: 'UTC', hour12: false }) + ' UTC'
                : '—'}
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
