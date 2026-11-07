import { useCallback, useEffect, useRef, useState } from 'react'
import { clearKnownSession, hasKnownSession, inspectSession, rememberSession, signOut } from '../services/auth'
import type { AuthResult } from '../services/auth'
import AnalystDashboard from './AnalystDashboard'
import AssessmentPage from './AssessmentPage'
import './Login.css'

const analyst = {
  path: '/analyst/dashboard',
  title: 'Security Analyst Dashboard',
  description: 'The analyst workspace is available.',
}
const administrator = {
  path: '/admin/dashboard',
  title: 'Administrator Dashboard',
  description: 'The administrator workspace is available.',
}

function workspaceFor(role: AuthResult['role']) {
  if (role === 'Security Analyst') return analyst
  if (role === 'Technical Administrator') return administrator
  return null
}

export default function Dashboard({ onSessionEnded, assessmentPath, createdBy, navigate }: {
  onSessionEnded: (expired?: boolean) => void
  assessmentPath?: string
  createdBy?: string
  navigate: (path: string, createdBy?: string) => void
}) {
  const [session, setSession] = useState<AuthResult | null>(null)
  const [unavailable, setUnavailable] = useState(false)
  const [retry, setRetry] = useState(0)
  const [signingOut, setSigningOut] = useState(false)
  const [logoutFailed, setLogoutFailed] = useState(false)
  const logoutInFlight = useRef(false)
  const previousAnalyst = useRef<string | undefined>(undefined)
  const [accountChanged, setAccountChanged] = useState(false)

  useEffect(() => {
    const controller = new AbortController()
    let checking = false

    async function verify() {
      if (checking || logoutInFlight.current || controller.signal.aborted) return
      checking = true
      if (!assessmentPath) setSession(null)
      setUnavailable(false)
      try {
        const result = await inspectSession(controller.signal)
        if (controller.signal.aborted) return
        if (result.state === 'authenticated') {
          if (!result.csrf_token) throw new Error('Missing session CSRF token')
          if (assessmentPath) {
            if (result.role === 'Security Analyst' && !result.user_id) throw new Error('Missing analyst identity')
            if (previousAnalyst.current && previousAnalyst.current !== result.user_id) setAccountChanged(true)
            previousAnalyst.current = result.user_id ?? undefined
          }
          rememberSession()
          setSession(result)
          const workspace = workspaceFor(result.role)
          window.history.replaceState(null, '', result.role === 'Security Analyst' && assessmentPath ? assessmentPath : workspace?.path ?? '/')
        } else {
          const expired = result.state === 'session_expired' || hasKnownSession()
          clearKnownSession()
          onSessionEnded(expired)
        }
      } catch {
        if (!controller.signal.aborted) {
          setSession(null)
          setUnavailable(true)
        }
      } finally {
        checking = false
      }
    }

    function onVisible() {
      if (document.visibilityState === 'visible') void verify()
    }

    void verify()
    const interval = window.setInterval(() => { void verify() }, 30000)
    window.addEventListener('focus', onVisible)
    document.addEventListener('visibilitychange', onVisible)
    return () => {
      controller.abort()
      window.clearInterval(interval)
      window.removeEventListener('focus', onVisible)
      document.removeEventListener('visibilitychange', onVisible)
    }
  }, [assessmentPath, onSessionEnded, retry])

  async function logout() {
    if (!session?.csrf_token || logoutInFlight.current) return
    logoutInFlight.current = true
    setSigningOut(true)
    setLogoutFailed(false)
    try {
      await signOut(session.csrf_token)
      clearKnownSession()
      onSessionEnded()
    } catch {
      setLogoutFailed(true)
    } finally {
      logoutInFlight.current = false
      setSigningOut(false)
    }
  }

  const expire = useCallback(() => {
    clearKnownSession()
    onSessionEnded(true)
  }, [onSessionEnded])
  const workspace = workspaceFor(session?.role)

  if (session?.role === 'Security Analyst') {
    if (assessmentPath && session.user_id) return <AssessmentPage key={session.user_id} userId={session.user_id} path={assessmentPath} username={session.username ?? ''}
      csrfToken={session.csrf_token ?? ''} showCreated={!accountChanged && createdBy === session.user_id} navigate={navigate}
      onExpired={expire} signingOut={signingOut}
      logoutFailed={logoutFailed} onSignOut={() => void logout()} />

    return <AnalystDashboard state={{ status: 'unavailable' }} signingOut={signingOut}
      logoutFailed={logoutFailed} onSignOut={() => void logout()} />
  }

  return (
    <main className="login-page">
      <section className="login-card" aria-label="Workspace">
        {!session && (unavailable ? <>
          <p role="alert">The session service is temporarily unavailable.</p>
          <button type="button" className="login-submit" data-state="ready" onClick={() => setRetry(retry + 1)}>Retry</button>
        </> : <p role="status">Checking your session…</p>)}
        {session && <>
          <header className="login-heading">
            <h1>{workspace?.title ?? 'Workspace access unavailable'}</h1>
            <p>{workspace?.description ?? 'Your assigned role does not have a workspace.'}</p>
          </header>
          {logoutFailed && <p role="alert">Unable to sign out. Please try again.</p>}
          <button type="button" className="login-submit" data-state="ready" onClick={() => void logout()} disabled={signingOut}>
            {signingOut ? 'Signing out…' : 'Sign Out'}
          </button>
        </>}
      </section>
    </main>
  )
}
