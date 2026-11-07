import { useCallback, useEffect, useState } from 'react'
import Login from './components/Login'
import FirstLogin from './components/FirstLogin'
import Dashboard from './components/Dashboard'

function App() {
  const [path, setPath] = useState(() => window.location.pathname)
  const [sessionEnded, setSessionEnded] = useState(false)
  const showLogin = useCallback((expired = false) => {
    window.history.replaceState(null, '', '/')
    setSessionEnded(expired)
    setPath('/')
  }, [])
  const showWorkspace = useCallback(() => setPath('/workspace'), [])
  useEffect(() => {
    function onPopState() {
      setSessionEnded(false)
      setPath(window.location.pathname)
    }
    window.addEventListener('popstate', onPopState)
    return () => window.removeEventListener('popstate', onPopState)
  }, [])

  if (path === '/first-login') return <FirstLogin onChanged={showLogin} onSessionEnded={showLogin} />
  if (path === '/analyst/dashboard' || path === '/admin/dashboard' || path === '/workspace') {
    return <Dashboard key={path} onSessionEnded={showLogin} />
  }
  return <Login sessionEnded={sessionEnded} onAuthenticated={showWorkspace} onPasswordChangeRequired={() => {
    window.history.replaceState(null, '', '/first-login')
    setPath('/first-login')
  }} />
}

export default App
