import { useState } from 'react'
import Login from './components/Login'
import MfaVerification from './components/MfaVerification'

function App() {
  const [step, setStep] = useState<'login' | 'mfa'>(() => window.location.pathname === '/mfa' ? 'mfa' : 'login')
  const [completed, setCompleted] = useState(false)
  function showLogin(success: boolean) {
    window.history.replaceState(null, '', '/')
    setCompleted(success)
    setStep('login')
  }
  if (step === 'mfa') return <MfaVerification onBack={() => showLogin(false)} onAuthenticated={() => showLogin(true)} />
  return <Login initialSuccess={completed} onMfaRequired={() => {
    window.history.replaceState(null, '', '/mfa')
    setCompleted(false)
    setStep('mfa')
  }} />
}

export default App
