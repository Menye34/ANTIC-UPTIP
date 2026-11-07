import type { AuthResult } from './auth'

export function passwordMeetsRequirements(value: string): boolean {
  return Array.from(value).length >= 12 && Array.from(value).length <= 1024 &&
    /\p{Lu}/u.test(value) && /\p{Ll}/u.test(value) && /\p{Nd}/u.test(value) && /[\p{P}\p{S}]/u.test(value)
}

export async function passwordRequest(action: 'challenge' | 'change', csrf?: string | null,
  newPassword?: string, confirmation?: string, signal?: AbortSignal): Promise<AuthResult> {
  const response = await fetch(`/api/v1/auth/password/${action}`, {
    method: action === 'challenge' ? 'GET' : 'POST', credentials: 'same-origin',
    headers: action === 'change' ? { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf ?? '' } : undefined,
    body: action === 'change' ? JSON.stringify({ new_password: newPassword, confirmation }) : undefined,
    signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(15000)]) : AbortSignal.timeout(15000),
  })
  const result: AuthResult = await response.json()
  const allowed = ['password_change_required', 'password_mismatch', 'password_rejected', 'password_changed',
    'challenge_expired', 'unauthenticated', 'forbidden', 'rate_limited', 'invalid_request', 'unavailable']
  if (!allowed.includes(result.state) || (result.state === 'password_changed' && !response.ok)) throw new Error('Password change unavailable')
  return result
}
