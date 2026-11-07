export type AuthState = 'invalid_credentials' | 'account_unavailable' | 'password_change_required'
  | 'authenticated'
  | 'rate_limited' | 'unavailable' | 'invalid_request' | 'forbidden' | 'unauthenticated' | 'session_expired' | 'challenge_expired' | 'password_mismatch' | 'password_rejected' | 'password_changed'

export interface AuthResult {
  state: AuthState
  message: string
  next_step_available: boolean
  csrf_token: string | null
  role?: string | null
  retry_after_seconds?: number | null
}

export async function signIn(username: string, password: string): Promise<AuthResult> {
  const response = await fetch('/api/v1/auth/login', {
    method: 'POST', credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
    signal: AbortSignal.timeout(15000),
  })
  const result: AuthResult = await response.json()
  const states: AuthState[] = ['invalid_credentials', 'account_unavailable', 'password_change_required',
    'authenticated', 'rate_limited',
    'unavailable', 'invalid_request', 'forbidden', 'unauthenticated', 'session_expired']
  if (!states.includes(result.state) || (!response.ok && result.state === 'authenticated')) {
    throw new Error('Invalid authentication response')
  }
  return result
}

export function outcomeMessage(result: AuthResult): string {
  switch (result.state) {
    case 'invalid_credentials': return 'Unable to sign in. Check your credentials and try again.'
    case 'account_unavailable': return 'Your account is currently unavailable. Contact your administrator.'
    case 'password_change_required': return 'Password replacement is required. This step is not yet available. Contact your administrator.'
    case 'authenticated': return 'Authentication complete.'
    case 'rate_limited': return 'Too many sign-in attempts. Please try again later.'
    default: return 'Sign-in is temporarily unavailable. Please try again.'
  }
}

// This boolean is a UI hint only, never an authentication credential or authorization gate.
const SESSION_HINT = 'uptip.previously-authenticated'
let knownSession = false
export function rememberSession() {
  knownSession = true
  try { sessionStorage.setItem(SESSION_HINT, 'true') } catch { /* Storage may be unavailable. */ }
}
export function hasKnownSession() {
  try { return knownSession || sessionStorage.getItem(SESSION_HINT) === 'true' } catch { return knownSession }
}
export function clearKnownSession() {
  knownSession = false
  try { sessionStorage.removeItem(SESSION_HINT) } catch { /* No stored secrets to clear. */ }
}
export async function inspectSession(signal: AbortSignal): Promise<AuthResult> {
  const response = await fetch('/api/v1/auth/session', {
    credentials: 'same-origin',
    signal: AbortSignal.any([signal, AbortSignal.timeout(10000)]),
  })
  const result: AuthResult = await response.json()
  if ((response.ok && result.state === 'authenticated') ||
      (response.status === 401 && ['unauthenticated', 'session_expired'].includes(result.state))) return result
  throw new Error('Session inspection unavailable')
}

export async function signOut(csrfToken: string): Promise<void> {
  const response = await fetch('/api/v1/auth/logout', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'X-CSRF-Token': csrfToken },
    signal: AbortSignal.timeout(10000),
  })
  const result: AuthResult = await response.json()
  if ((response.ok || response.status === 401) && result.state === 'unauthenticated') return
  throw new Error('Sign out unavailable')
}
