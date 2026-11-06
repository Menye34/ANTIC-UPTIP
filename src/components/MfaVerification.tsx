import { useEffect, useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { acceptAuthenticatedSession } from '../services/auth'
import type { AuthResult } from '../services/auth'
import { mfaRequest } from '../services/mfa'
import AuthBrand from './AuthBrand'
import errorIcon from '../assets/login-error.svg'
import warningIcon from '../assets/mfa-warning.svg'
import infoIcon from '../assets/login-info.svg'
import './Login.css'
import './MfaVerification.css'

const INVALID = 'That code is incorrect. Check your authenticator app and try again.'
const EXPIRED = 'This code has expired. Enter the latest code from your authenticator app.'
const LOCKED = 'Too many attempts. Try again in 15 minutes or contact your administrator.'
type Notice = { message: string; tone: 'error' | 'warning' | 'info'; editable: boolean }

export default function MfaVerification({ onBack, onAuthenticated }: { onBack: () => void; onAuthenticated: () => void }) {
  const [code, setCode] = useState('')
  const [notice, setNotice] = useState<Notice | null>(null)
  const [ready, setReady] = useState(false)
  const [locked, setLocked] = useState(false)
  const [pending, setPending] = useState(false)
  const [cancelling, setCancelling] = useState(false)
  const csrf = useRef<string | null>(null)
  const inFlight = useRef(false)
  const version = useRef(0)
  const verification = useRef<AbortController | null>(null)

  function apply(result: AuthResult) {
    if (result.csrf_token) csrf.current = result.csrf_token
    switch (result.state) {
      case 'mfa_verification_required':
        setReady(true)
        setLocked(false)
        break
      case 'invalid_code':
        setNotice({ message: INVALID, tone: 'error', editable: true })
        break
      case 'code_expired':
        setCode('')
        setNotice({ message: EXPIRED, tone: 'warning', editable: true })
        break
      case 'too_many_attempts':
        setCode('')
        setLocked(true)
        setNotice({ message: LOCKED, tone: 'error', editable: false })
        break
      case 'authenticated':
        setCode('')
        csrf.current = null
        acceptAuthenticatedSession(result)
        onAuthenticated()
        break
      case 'challenge_expired': case 'unauthenticated':
        setReady(false)
        setLocked(false)
        setCode('')
        setNotice({ message: 'Your verification session has ended. Sign in again to continue.', tone: 'info', editable: false })
        break
      default:
        setNotice({ message: 'Verification is temporarily unavailable. Please try again.', tone: 'info', editable: false })
    }
  }

  useEffect(() => {
    const controller = new AbortController()
    const current = version.current
    mfaRequest('challenge', undefined, undefined, controller.signal).then((result) => {
      if (!controller.signal.aborted && current === version.current) apply(result)
    }).catch(() => {
      if (!controller.signal.aborted && current === version.current) setNotice({ message: 'Unable to reach the verification service. Try Back to Sign In to retry.', tone: 'info', editable: false })
    })
    return () => { controller.abort(); verification.current?.abort() }
    // State is initialized from the server once per pending flow, not from edited code.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (inFlight.current || !ready || locked || !/^\d{6}$/.test(code)) return
    inFlight.current = true
    const current = ++version.current
    verification.current = new AbortController()
    setPending(true)
    setNotice(null)
    try {
      const result = await mfaRequest('verify', csrf.current, code, verification.current.signal)
      if (current === version.current) apply(result)
    } catch {
      if (current === version.current) setNotice({ message: 'Unable to reach the verification service. Please try again.', tone: 'info', editable: false })
    } finally {
      if (current === version.current) { inFlight.current = false; setPending(false) }
    }
  }

  async function back() {
    if (cancelling) return
    version.current += 1
    verification.current?.abort()
    setCode('')
    setCancelling(true)
    try {
      // Refresh a missing CSRF token after reload or a prior network failure.
      if (!csrf.current) {
        const context = await mfaRequest('challenge')
        csrf.current = context.csrf_token
      }
      const result = await mfaRequest('cancel', csrf.current)
      if (result.state !== 'mfa_cancelled') throw new Error('Cancellation unavailable')
      csrf.current = null
      onBack()
    } catch {
      inFlight.current = false
      setPending(false)
      setNotice({ message: 'Unable to cancel verification. Please try again.', tone: 'info', editable: false })
    } finally { setCancelling(false) }
  }

  const busy = pending || cancelling
  return <main className="login-page">
    <form className="login-card mfa-card" aria-labelledby="mfa-heading" aria-busy={busy} onSubmit={submit}>
      <AuthBrand />
      <header className="login-heading">
        <h1 id="mfa-heading">Verify your identity</h1>
        <p>Enter the 6-digit code from your authenticator app.</p>
      </header>
      {notice && <div className={`login-alert login-alert--${notice.tone}`} role={notice.tone === 'error' ? 'alert' : 'status'}>
        <img src={notice.tone === 'error' ? errorIcon : notice.tone === 'warning' ? warningIcon : infoIcon} width="20" height="20" alt="" />
        <p>{notice.message}</p>
      </div>}
      <div className="login-field">
        <label htmlFor="verification-code">Verification code</label>
        <input id="verification-code" name="verification-code" type="text" inputMode="numeric" autoComplete="one-time-code"
          placeholder="Enter verification code" maxLength={6} pattern="[0-9]{6}" required value={code}
          disabled={busy || locked || !ready} aria-invalid={notice?.message === INVALID}
          onChange={(event) => {
            const value = event.target.value
            if (!/^[0-9]{0,6}$/.test(value)) return
            setCode(value)
            if (notice?.editable) setNotice(null)
          }} />
      </div>
      <button className="login-submit" type="submit" data-state={!busy && !locked && ready && code.length === 6 ? 'ready' : 'disabled'}
        disabled={busy || locked || !ready || code.length !== 6}>{pending ? 'Verifying...' : 'Verify'}</button>
      <div className="mfa-return"><button type="button" className="mfa-back" disabled={cancelling} onClick={() => { void back() }}>Back to Sign In</button></div>
    </form>
  </main>
}
