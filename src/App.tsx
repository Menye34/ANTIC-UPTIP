import { useState } from 'react'
import Login from './components/Login'
import FirstLogin from './components/FirstLogin'

function App() {
  const [step, setStep] = useState<'login' | 'first-login'>(() => window.location.pathname === '/first-login' ? 'first-login' : 'login')
  function showLogin() {
    window.history.replaceState(null, '', '/')
    setStep('login')
  }
  if (step === 'first-login') return <FirstLogin onChanged={showLogin} onSessionEnded={showLogin} />
  return <Login onPasswordChangeRequired={() => {
    window.history.replaceState(null, '', '/first-login')
    setStep('first-login')
  }} />
}

export default App
