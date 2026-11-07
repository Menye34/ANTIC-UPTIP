import { useEffect, useRef, useState } from 'react'
import type { FormEvent } from 'react'
import AuthBrand from './AuthBrand'
import { clearKnownSession } from '../services/auth'
import { passwordMeetsRequirements, passwordRequest } from '../services/password'
import errorIcon from '../assets/login-error.svg'
import infoIcon from '../assets/login-info.svg'
import hiddenIcon from '../assets/password-visibility.svg'
import visibleIcon from '../assets/password-visible.svg'
import './Login.css'
import './FirstLogin.css'

const MISMATCH = 'Passwords do not match. Re-enter your new password.'
type Notice = { message: string; error: boolean }

export default function FirstLogin({ onChanged, onSessionEnded }: { onChanged: () => void; onSessionEnded: () => void }) {
  const [password, setPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [visible, setVisible] = useState([false, false])
  const [notice, setNotice] = useState<Notice | null>(null)
  const [ready, setReady] = useState(false)
  const [pending, setPending] = useState(false)
  const csrf = useRef<string | null>(null)
  const inFlight = useRef(false)
  const request = useRef<AbortController | null>(null)
  const version = useRef(0)
  const allowed = ready && passwordMeetsRequirements(password) && password === confirmation

  useEffect(() => {
    const controller = new AbortController()
    passwordRequest('challenge', undefined, undefined, undefined, controller.signal).then((result) => {
      if (controller.signal.aborted) return
      if (result.state === 'password_change_required' && result.next_step_available && result.csrf_token) {
        csrf.current = result.csrf_token
        setReady(true)
      } else if (result.state === 'challenge_expired' || result.state === 'unauthenticated') {
        onSessionEnded()
      } else {
        setNotice({ message: 'Password change is unavailable. Refresh the page to try again.', error: false })
      }
    }).catch(() => {
      if (!controller.signal.aborted) setNotice({ message: 'Unable to reach the password service. Refresh the page to try again.', error: false })
    })
    return () => { version.current += 1; controller.abort(); request.current?.abort() }
    // Validate the server challenge once per mounted flow; never infer authorization from the URL.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (inFlight.current || !ready) return
    if (password !== confirmation) { setNotice({ message: MISMATCH, error: true }); return }
    if (!allowed) return
    inFlight.current = true
    const current = ++version.current
    request.current = new AbortController()
    setPending(true)
    setVisible([false, false])
    setNotice(null)
    try {
      const result = await passwordRequest('change', csrf.current, password, confirmation, request.current.signal)
      if (current !== version.current) return
      if (result.state === 'password_changed') {
        setPassword(''); setConfirmation(''); csrf.current = null
        clearKnownSession()
        onChanged()
      } else if (result.state === 'challenge_expired' || result.state === 'unauthenticated') {
        setPassword(''); setConfirmation(''); csrf.current = null
        onSessionEnded()
      } else if (result.state === 'password_mismatch') {
        setNotice({ message: MISMATCH, error: true })
      } else if (result.state === 'password_rejected') {
        setNotice({ message: result.message, error: true })
      } else {
        setNotice({ message: result.state === 'rate_limited' ? 'Too many attempts. Please try again later.' :
          'Password change is temporarily unavailable. Please try again.', error: false })
      }
    } catch {
      if (current === version.current) setNotice({ message: 'Unable to reach the password service. Please try again.', error: false })
    } finally {
      if (current === version.current) { inFlight.current = false; setPending(false) }
    }
  }

  return <main className="login-page">
    <form className="login-card first-login-card" aria-labelledby="first-login-heading" aria-busy={pending} onSubmit={submit}>
      <AuthBrand />
      <header className="login-heading">
        <h1 id="first-login-heading">Set a new password</h1>
        <p>Your account uses a temporary password. Create a new one to continue.</p>
      </header>
      {notice && <div className={`login-alert login-alert--${notice.error ? 'error' : 'info'}`} role={notice.error ? 'alert' : 'status'}>
        <img src={notice.error ? errorIcon : infoIcon} width="20" height="20" alt="" /><p>{notice.message}</p>
      </div>}
      <div className="login-fields">
        {[
          { id: 'new-password', label: 'New password', placeholder: 'Enter new password', value: password },
          { id: 'confirm-password', label: 'Confirm new password', placeholder: 'Confirm your new password', value: confirmation },
        ].map((field, index) => <div className="login-field" key={field.id}>
          <label htmlFor={field.id}>{field.label}</label>
          <div className="login-password">
            <input id={field.id} name={field.id} type={visible[index] ? 'text' : 'password'} autoComplete="new-password"
              placeholder={field.placeholder} value={field.value} maxLength={1024} required disabled={pending || !ready}
              aria-describedby="password-requirements"
              onChange={(event) => {
                if (index === 0) setPassword(event.target.value); else setConfirmation(event.target.value)
                setNotice(null)
              }}
              onBlur={() => {
                if (index === 1 && password && confirmation && password !== confirmation) setNotice({ message: MISMATCH, error: true })
              }} />
            <button type="button" className="login-password-toggle" disabled={pending || !ready}
              aria-label={`${visible[index] ? 'Hide' : 'Show'} ${field.label.toLowerCase()}`}
              aria-pressed={visible[index]} aria-controls={field.id}
              onClick={() => setVisible((current) => current.map((value, i) => i === index ? !value : value))}>
              <img src={visible[index] ? visibleIcon : hiddenIcon} width="16" height="16" alt="" />
            </button>
          </div>
        </div>)}
      </div>
      <p id="password-requirements" className="first-login-requirements">Use at least 12 characters, with upper and lower case letters, a number and a symbol.</p>
      <button type="submit" className="login-submit" data-state={allowed && !pending ? 'ready' : 'disabled'} disabled={!allowed || pending}>Set new password</button>
      <p className="login-help">Need help signing in? Contact your administrator.</p>
    </form>
  </main>
}
