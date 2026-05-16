import { Flame } from 'lucide-react'
import type { Page } from '../App'

interface TopBarProps {
  page: Page
  setPage: (p: Page) => void
  labReady: boolean
  containersRunning: number
}

const NAV: { id: Page; label: string }[] = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'scenarios', label: 'Scenarios' },
  { id: 'results', label: 'Results' },
]

export function TopBar({ page, setPage, labReady, containersRunning }: TopBarProps) {
  return (
    <header className="topbar">
      <div className="topbar-logo">
        <Flame size={20} />
        Gloamfire
      </div>

      <nav className="topbar-nav">
        {NAV.map((n) => (
          <button
            key={n.id}
            className={`topbar-nav-link${page === n.id ? ' active' : ''}`}
            onClick={() => setPage(n.id)}
          >
            {n.label}
          </button>
        ))}
      </nav>

      <div className="topbar-right">
        <div className={`lab-status-dot${labReady ? ' ready' : ' offline'}`} title={labReady ? `${containersRunning} containers running` : 'Lab offline'} />
        <span style={{ fontSize: 12, color: 'var(--text-dim)' }}>
          {labReady ? `${containersRunning} up` : 'offline'}
        </span>
      </div>
    </header>
  )
}
