import { useEffect, useCallback } from 'react'
import { X, ExternalLink } from 'lucide-react'
import { type MitreTechnique } from '../api/client'

const TACTIC_COLOR: Record<string, string> = {
  'Execution':            'var(--accent)',
  'Persistence':          '#a78bfa',
  'Privilege Escalation': '#f59e0b',
  'Defense Evasion':      '#6ee7b7',
  'Credential Access':    'var(--red)',
  'Discovery':            'var(--blue)',
  'Lateral Movement':     '#f472b6',
  'Collection':           '#34d399',
  'Exfiltration':         '#fb923c',
  'Command and Control':  '#60a5fa',
  'Impact':               '#ef4444',
  'Initial Access':       '#818cf8',
}

export function TechniqueModal({ technique, onClose }: { technique: MitreTechnique; onClose: () => void }) {
  const onKey = useCallback((e: KeyboardEvent) => {
    if (e.key === 'Escape') onClose()
  }, [onClose])

  useEffect(() => {
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onKey])

  const tacticColor = TACTIC_COLOR[technique.tactic] ?? 'var(--text-dim)'
  const isSubTechnique = technique.id.includes('.')

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-box" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontFamily: 'var(--mono)', color: 'var(--accent)', fontWeight: 700, fontSize: 14 }}>
              {technique.id}
            </span>
            <span className="modal-title">{technique.name}</span>
          </div>
          <button className="modal-close" onClick={onClose}><X size={16} /></button>
        </div>

        <div className="modal-body">
          <div className="modal-row">
            <span className="modal-row-label">Tactic</span>
            <span style={{ color: tacticColor, fontWeight: 600, fontSize: 13 }}>{technique.tactic}</span>
          </div>

          <div className="modal-row">
            <span className="modal-row-label">Type</span>
            <span className="modal-row-value">{isSubTechnique ? 'Sub-technique' : 'Technique'}</span>
          </div>

          {isSubTechnique && (
            <div className="modal-row">
              <span className="modal-row-label">Parent</span>
              <span className="modal-row-value mono">{technique.id.split('.')[0]}</span>
            </div>
          )}

          <div className="modal-section">
            <a
              className="ctrl-btn"
              href={technique.url}
              target="_blank"
              rel="noreferrer"
              style={{ textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: 6 }}
            >
              <ExternalLink size={13} /> View on MITRE ATT&amp;CK ↗
            </a>
          </div>
        </div>
      </div>
    </div>
  )
}
