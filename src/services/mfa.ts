import type { AuthResult } from './auth'

const outcomes = ['mfa_verification_required', 'invalid_code', 'code_expired', 'too_many_attempts',
  'authenticated', 'challenge_expired', 'unauthenticated', 'forbidden', 'invalid_request',
  'unavailable', 'mfa_cancelled', 'rate_limited']

export async function mfaRequest(action: 'challenge' | 'verify' | 'cancel', csrf?: string | null, code?: string, signal?: AbortSignal): Promise<AuthResult> {
  const response = await fetch(`/api/v1/auth/mfa/${action}`, {
    method: action === 'challenge' ? 'GET' : 'POST', credentials: 'same-origin',
    headers: action === 'challenge' ? undefined : { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf ?? '' },
    body: action === 'verify' ? JSON.stringify({ code }) : undefined,
    signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(15000)]) : AbortSignal.timeout(15000),
  })
  const result: AuthResult = await response.json()
  if (!outcomes.includes(result.state) || (result.state === 'authenticated' && !response.ok)) throw new Error('Verification unavailable')
  return result
}
