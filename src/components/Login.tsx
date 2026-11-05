import { useEffect, useRef, useState } from 'react'
import type { FormEvent, KeyboardEvent } from 'react'
import { clearKnownSession, hasKnownSession, inspectSession, outcomeMessage, rememberSession, signIn } from '../services/auth'
import uptipLogo from '../assets/uptip-logo.svg'
import passwordHiddenIcon from '../assets/password-visibility.svg'
import passwordVisibleIcon from '../assets/password-visible.svg'
import errorIcon from '../assets/login-error.svg'
import infoIcon from '../assets/login-info.svg'
import './Login.css'

type Notice = { message: string; tone: 'error' | 'info'; dismissOnEdit?: boolean }
const SESSION_ENDED = 'Your session has ended. Sign in again to continue.'

/** Authentication Login scenarios: actual Figma frames, without review wrappers. */
export default function Login() {
  const [passwordVisible, setPasswordVisible] = useState(false)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [capsLock, setCapsLock] = useState(false)
  const [pending, setPending] = useState(false)
  const [notice, setNotice] = useState<Notice | null>(null)
  const inFlight = useRef(false)
  const generation = useRef(0)
  const ready = username.trim().length > 0 && password.length > 0

  useEffect(() => {
    const controller = new AbortController()
    let checking = false
    async function check() {
      if (checking || inFlight.current || controller.signal.aborted) return
      checking = true
      const version = generation.current
      const previouslyAuthenticated = hasKnownSession()
      try {
        const result = await inspectSession(controller.signal)
        if (controller.signal.aborted || inFlight.current || version !== generation.current) return
        if (result.state === 'authenticated') {
          rememberSession()
        } else if (result.state === 'session_expired' || (result.state === 'unauthenticated' && previouslyAuthenticated)) {
          clearKnownSession()
          setUsername('')
          setPassword('')
          setPasswordVisible(false)
          setCapsLock(false)
          setNotice({ message: SESSION_ENDED, tone: 'info', dismissOnEdit: true })
        }
      } catch {
        // A network outage is not proof of session expiry. Check again later.
      } finally {
        checking = false
      }
    }
    function onVisible() { if (document.visibilityState === 'visible') void check() }
    void check()
    const interval = window.setInterval(() => { void check() }, 30000)
    window.addEventListener('focus', onVisible)
    document.addEventListener('visibilitychange', onVisible)
    return () => {
      controller.abort()
      window.clearInterval(interval)
      window.removeEventListener('focus', onVisible)
      document.removeEventListener('visibilitychange', onVisible)
    }
  }, [])

  function detectCapsLock(event: KeyboardEvent<HTMLInputElement>) {
    setCapsLock(event.getModifierState('CapsLock'))
  }

  function credentialsChanged() {
    // A session check started for older input must not restore a dismissed notice.
    generation.current += 1
    setNotice((current) => current?.dismissOnEdit ? null : current)
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (inFlight.current || !ready) return
    const version = ++generation.current
    inFlight.current = true
    setPending(true)
    setNotice(null)
    setPasswordVisible(false)
    try {
      const result = await signIn(username, password)
      if (version !== generation.current) return
      const error = result.state === 'invalid_credentials'
      setNotice({ message: outcomeMessage(result), tone: error ? 'error' : 'info',
        dismissOnEdit: error || result.state === 'account_unavailable' })
      // Figma retains both values for invalid credentials; unavailable clears only password.
      if (result.state !== 'invalid_credentials') setPassword('')
      if (result.state === 'authenticated') rememberSession()
      // No dashboard, MFA or password-replacement navigation is implemented here.
    } catch {
      if (version !== generation.current) return
      setNotice({ message: 'Unable to reach the sign-in service. Please try again.', tone: 'info' })
    } finally {
      inFlight.current = false
      setPending(false)
    }
  }

  return (
    <main className="login-page">
      <form className="login-card" aria-labelledby="login-heading" onSubmit={submit} aria-busy={pending}
        onBlur={(event) => { if (!event.currentTarget.contains(event.relatedTarget)) setCapsLock(false) }}>
        <div className="login-brand">
          <p className="login-institution">ANTIC</p>
          <img className="login-logo" src={uptipLogo} width="108" height="25" alt="UPTIP" />
          <p className="login-platform-name">Unified Penetration Testing Intelligent Platform</p>
        </div>
        <header className="login-heading">
          <h1 id="login-heading">Sign in to UPTIP</h1>
          <p>Secure access for authorized users.</p>
        </header>
        {notice && <div id="login-notice" className={`login-alert login-alert--${notice.tone}`}
          role={notice.tone === 'error' ? 'alert' : 'status'} aria-live={notice.tone === 'error' ? 'assertive' : 'polite'}>
          <img src={notice.tone === 'error' ? errorIcon : infoIcon} width="20" height="20" alt="" />
          <p>{notice.message}</p>
        </div>}
        <div className="login-fields">
          <div className="login-field">
            <label htmlFor="username">Username</label>
            <input id="username" name="username" type="text" autoComplete="username" disabled={pending}
              autoCapitalize="none" spellCheck={false} placeholder="Enter your username" value={username} required maxLength={128}
              onKeyDown={detectCapsLock} onKeyUp={detectCapsLock}
              onChange={(event) => { setUsername(event.target.value); credentialsChanged() }} />
          </div>
          <div className="login-field">
            <label htmlFor="password">Password</label>
            <div className="login-password">
              <input id="password" name="password" type={passwordVisible ? 'text' : 'password'} disabled={pending}
                autoComplete="current-password" placeholder="Enter your password" value={password} required maxLength={1024}
                aria-describedby={capsLock && !pending ? 'login-caps-lock' : undefined}
                onKeyDown={detectCapsLock} onKeyUp={detectCapsLock}
                onChange={(event) => { setPassword(event.target.value); credentialsChanged() }} />
              <button className="login-password-toggle" type="button" disabled={pending}
                aria-label={passwordVisible ? 'Hide password' : 'Show password'}
                aria-pressed={passwordVisible} aria-controls="password"
                onClick={() => setPasswordVisible((visible) => !visible)}>
                <img src={passwordVisible ? passwordVisibleIcon : passwordHiddenIcon} width="16" height="16" alt="" />
              </button>
            </div>
          </div>
          {capsLock && !pending && <p id="login-caps-lock" className="login-caps-lock" role="status">Caps Lock is on</p>}
        </div>
        <button className="login-submit" type="submit" data-state={pending ? 'signing-in' : ready ? 'ready' : 'disabled'} disabled={pending || !ready}>
          {pending ? 'Signing in...' : 'Sign In'}
        </button>
        <p className="login-help">Need help signing in? Contact your administrator.</p>
      </form>
    </main>
  )
}
