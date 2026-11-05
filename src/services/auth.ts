export type AuthState = 'invalid_credentials' | 'account_unavailable' | 'password_change_required'
  | 'mfa_verification_required' | 'mfa_enrollment_required' | 'authenticated'
  | 'rate_limited' | 'unavailable' | 'invalid_request' | 'forbidden' | 'unauthenticated'

export interface AuthResult {
  state: AuthState
  message: string
  next_step_available: boolean
  csrf_token: string | null
}

// Held only in memory for future cookie-authenticated mutations; never persisted.
let csrfToken: string | null = null
export function getCsrfToken() { return csrfToken }

export async function signIn(username: string, password: string): Promise<AuthResult> {
  const response = await fetch('/api/v1/auth/login', {
    method: 'POST', credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
    signal: AbortSignal.timeout(15000),
  })
  const result: AuthResult = await response.json()
  const states: AuthState[] = ['invalid_credentials', 'account_unavailable', 'password_change_required',
    'mfa_verification_required', 'mfa_enrollment_required', 'authenticated', 'rate_limited',
    'unavailable', 'invalid_request', 'forbidden', 'unauthenticated']
  if (!states.includes(result.state) || (!response.ok && result.state === 'authenticated')) {
    throw new Error('Invalid authentication response')
  }
  csrfToken = result.state === 'authenticated' ? result.csrf_token : null
  return result
}

export function outcomeMessage(result: AuthResult): string {
  switch (result.state) {
    case 'invalid_credentials': return 'Unable to sign in. Check your credentials and try again.'
    case 'account_unavailable': return 'Your account is currently unavailable. Contact your administrator.'
    case 'password_change_required': return 'Password replacement is required. This step is not yet available. Contact your administrator.'
    case 'mfa_verification_required': return 'MFA verification is required. This step is not yet available.'
    case 'mfa_enrollment_required': return 'MFA enrollment is required. This step is not yet available. Contact your administrator.'
    case 'authenticated': return 'Authentication complete.'
    case 'rate_limited': return 'Too many sign-in attempts. Please try again later.'
    default: return 'Sign-in is temporarily unavailable. Please try again.'
  }
}
