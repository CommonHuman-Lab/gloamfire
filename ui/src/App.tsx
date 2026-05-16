import { useState, useEffect, useCallback } from 'react'
import { TopBar } from './components/TopBar'
import { DashboardPage } from './pages/Dashboard/DashboardPage'
import { ScenariosPage } from './pages/Scenarios/ScenariosPage'
import { ResultsPage } from './pages/Results/ResultsPage'
import { api } from './api/client'
import './App.css'

export type Page = 'dashboard' | 'scenarios' | 'results'

function pageFromHash(): Page {
  const h = window.location.hash.replace('#/', '').split('?')[0]
  if (h === 'scenarios') return 'scenarios'
  if (h === 'results') return 'results'
  return 'dashboard'
}

export default function App() {
  const [page, setPageState] = useState<Page>(pageFromHash)
  const [labReady, setLabReady] = useState(false)
  const [containersRunning, setContainersRunning] = useState(0)

  function setPage(p: Page) {
    setPageState(p)
    window.location.hash = p === 'dashboard' ? '/' : `/${p}`
  }

  useEffect(() => {
    const onHash = () => setPageState(pageFromHash())
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  const pollStatus = useCallback(async () => {
    try {
      const s = await api.getStatus()
      setLabReady(s.lab_ready)
      setContainersRunning(s.containers_running)
    } catch {
      setLabReady(false)
    }
  }, [])

  useEffect(() => {
    void pollStatus()
    const id = setInterval(() => void pollStatus(), 15_000)
    return () => clearInterval(id)
  }, [pollStatus])

  return (
    <div className="layout">
      <TopBar page={page} setPage={setPage} labReady={labReady} containersRunning={containersRunning} />
      <main className="main-content">
        {page === 'dashboard' && <DashboardPage />}
        {page === 'scenarios' && <ScenariosPage />}
        {page === 'results' && <ResultsPage />}
      </main>
    </div>
  )
}
