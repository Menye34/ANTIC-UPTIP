import { useState } from 'react'
import Login from './components/Login'
import MfaVerification from './components/MfaVerification'
import FirstLogin from './components/FirstLogin'

function App() {
  const [step, setStep] = useState<'login' | 'mfa' | 'first-login'>(() => window.location.pathname === '/first-login' ? 'first-login' : window.location.pathname === '/mfa' ? 'mfa' : 'login')
  const [completed, setCompleted] = useState(false)
  function showLogin(success: boolean) {
    window.history.replaceState(null, '', '/')
    setCompleted(success)
    setStep('login')
  }
  if (step === 'first-login') return <FirstLogin onChanged={() => showLogin(false)} onSessionEnded={() => showLogin(false)} />
  if (step === 'mfa') return <MfaVerification onBack={() => showLogin(false)} onAuthenticated={() => showLogin(true)} />
  return <Login initialSuccess={completed} onPasswordChangeRequired={() => {
    window.history.replaceState(null, '', '/first-login')
    setCompleted(false)
    setStep('first-login')
  }} onMfaRequired={() => {
    window.history.replaceState(null, '', '/mfa')
    setCompleted(false)
    setStep('mfa')
  }} />
}

export default App
