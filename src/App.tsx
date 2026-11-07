import { useCallback, useEffect, useState } from 'react'
import Login from './components/Login'
import FirstLogin from './components/FirstLogin'
import Dashboard from './components/Dashboard'

function App() {
  const [path, setPath] = useState(() => window.location.pathname)
  const [creation, setCreation] = useState<{ path: string; userId: string } | null>(null)
  const [sessionEnded, setSessionEnded] = useState(false)
  const showLogin = useCallback((expired = false) => {
    window.history.replaceState(null, '', '/')
    setSessionEnded(expired)
    setCreation(null)
    setPath('/')
  }, [])
  const navigate = useCallback((nextPath: string, createdBy?: string) => {
    window.history.pushState(null, '', nextPath)
    setCreation(createdBy ? { path: nextPath, userId: createdBy } : null)
    setPath(nextPath)
  }, [])
  const showWorkspace = useCallback(() => setPath('/workspace'), [])
  useEffect(() => {
    function onPopState() {
      setSessionEnded(false)
      setCreation(null)
      setPath(window.location.pathname)
    }
    window.addEventListener('popstate', onPopState)
    return () => window.removeEventListener('popstate', onPopState)
  }, [])

  if (path === '/first-login') return <FirstLogin onChanged={showLogin} onSessionEnded={showLogin} />
  const assessmentPath = /^\/analyst\/assessments\/[^/]+(?:\/scope)?$/.test(path) ? path : undefined
  if (assessmentPath || path === '/analyst/dashboard' || path === '/admin/dashboard' || path === '/workspace') {
    return <Dashboard key={path} onSessionEnded={showLogin} assessmentPath={assessmentPath}
      createdBy={creation?.path === path ? creation.userId : undefined} navigate={navigate} />
  }
  return <Login sessionEnded={sessionEnded} onAuthenticated={showWorkspace} onPasswordChangeRequired={() => {
    window.history.replaceState(null, '', '/first-login')
    setPath('/first-login')
  }} />
}

export default App
