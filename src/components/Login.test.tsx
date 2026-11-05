import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import Login from './Login'

afterEach(() => vi.unstubAllGlobals())
const result = (state: string, ok = true) => ({ ok, json: async () => ({ state, next_step_available: false, csrf_token: null }) })
async function fill() {
  const user = userEvent.setup()
  await user.type(screen.getByLabelText('Username'), 'analyst-01')
  await user.type(screen.getByLabelText('Password'), 'test-password')
  return user
}

describe('Login integration', () => {
  it('renders Default with empty fields and disabled submit', () => {
    const fetcher = vi.fn()
    vi.stubGlobal('fetch', fetcher)
    render(<Login />)
    expect(screen.getByRole('heading', { name: 'Sign in to UPTIP' })).toBeVisible()
    expect(screen.getByLabelText('Username')).toHaveValue('')
    expect(screen.getByLabelText('Password')).toHaveValue('')
    expect(screen.getByRole('button', { name: 'Sign In' })).toBeDisabled()
    fireEvent.submit(screen.getByRole('button', { name: 'Sign In' }).closest('form')!)
    expect(fetcher).not.toHaveBeenCalled()
  })
  it('submits credentials once, shows loading, and handles invalid credentials', async () => {
    let finish!: (value: unknown) => void
    const fetcher = vi.fn(() => new Promise((resolve) => { finish = resolve }))
    vi.stubGlobal('fetch', fetcher)
    render(<Login />)
    const user = await fill()
    await user.click(screen.getByRole('button', { name: 'Sign In' }))
    expect(screen.getByRole('button', { name: 'Signing in...' })).toBeDisabled()
    fireEvent.submit(screen.getByRole('button', { name: 'Signing in...' }).closest('form')!)
    expect(fetcher).toHaveBeenCalledTimes(1)
    expect(fetcher.mock.calls[0]).toEqual(['/api/v1/auth/login', expect.objectContaining({
      method: 'POST', credentials: 'same-origin',
      body: JSON.stringify({ username: 'analyst-01', password: 'test-password' }),
    })])
    finish(result('invalid_credentials', false))
    expect(await screen.findByRole('status')).toHaveTextContent('Unable to sign in. Check your credentials and try again.')
    expect(screen.getByLabelText('Password')).toHaveValue('')
  })
  it('handles network failures and permits retry', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('offline')))
    render(<Login />)
    const user = await fill()
    await user.click(screen.getByRole('button', { name: 'Sign In' }))
    expect(await screen.findByRole('status')).toHaveTextContent('Unable to reach the sign-in service.')
    await user.type(screen.getByLabelText('Password'), 'retry')
    expect(screen.getByRole('button', { name: 'Sign In' })).toBeEnabled()
  })
  it.each(['password_change_required', 'mfa_enrollment_required', 'mfa_verification_required'])(
    'does not claim completion or navigate for %s', async (state) => {
      const href = window.location.href
      vi.stubGlobal('fetch', vi.fn().mockResolvedValue(result(state)))
      render(<Login />)
      const user = await fill()
      await user.click(screen.getByRole('button', { name: 'Sign In' }))
      await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('not yet available'))
      expect(window.location.href).toBe(href)
      expect(screen.queryByText('Authentication complete.')).not.toBeInTheDocument()
    })
  it('stays on Login after genuine authenticated response', async () => {
    const href = window.location.href
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(result('authenticated')))
    render(<Login />)
    const user = await fill()
    await user.click(screen.getByRole('button', { name: 'Sign In' }))
    expect(await screen.findByRole('status')).toHaveTextContent('Authentication complete.')
    expect(window.location.href).toBe(href)
  })
})

it.each([
  ['account_unavailable', 'Your account is currently unavailable. Contact your administrator.'],
  ['unavailable', 'Sign-in is temporarily unavailable. Please try again.'],
  ['rate_limited', 'Too many sign-in attempts. Please try again later.'],
])('handles %s without navigation', async (state, message) => {
  const href = window.location.href
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(result(state, false)))
  render(<Login />)
  const user = await fill()
  await user.click(screen.getByRole('button', { name: 'Sign In' }))
  expect(await screen.findByRole('status')).toHaveTextContent(message)
  expect(window.location.href).toBe(href)
})
