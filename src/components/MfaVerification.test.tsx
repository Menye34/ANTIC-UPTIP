/// <reference types="node" />
import { readFileSync } from 'node:fs'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import MfaVerification from './MfaVerification'
import App from '../App'
import { clearKnownSession } from '../services/auth'

const styles = document.createElement('style')
beforeAll(() => {
  styles.textContent = readFileSync('src/components/Login.css', 'utf8') + readFileSync('src/components/MfaVerification.css', 'utf8')
  document.head.append(styles)
})
afterAll(() => styles.remove())
const back = vi.fn()
const authenticated = vi.fn()
const response = (state: string, status = 200) => ({ ok: status < 400, status,
  json: async () => ({ state, csrf_token: state === 'authenticated' ? 'authenticated-csrf-fixture' : 'pending-csrf-fixture', next_step_available: true }) })
let sessionAuthenticated = false
let verify = vi.fn<(...args: unknown[]) => Promise<unknown>>()
let cancel = vi.fn<(...args: unknown[]) => Promise<unknown>>()
let fetcher = vi.fn<(...args: unknown[]) => Promise<unknown>>()
beforeEach(() => {
  back.mockReset(); authenticated.mockReset(); clearKnownSession()
  sessionAuthenticated = false
  window.history.replaceState(null, '', '/')
  verify = vi.fn().mockResolvedValue(response('invalid_code', 401))
  cancel = vi.fn().mockResolvedValue(response('mfa_cancelled'))
  fetcher = vi.fn((...args) => {
    const [url] = args
    if (url === '/api/v1/auth/mfa/verify') return verify(...args)
    if (url === '/api/v1/auth/mfa/cancel') return cancel(...args)
    if (url === '/api/v1/auth/session') return Promise.resolve(response(sessionAuthenticated ? 'authenticated' : 'unauthenticated', sessionAuthenticated ? 200 : 401))
    if (url === '/api/v1/auth/login') return Promise.resolve(response('mfa_verification_required'))
    return Promise.resolve(response('mfa_verification_required'))
  })
  vi.stubGlobal('fetch', fetcher)
})
afterEach(() => { vi.unstubAllGlobals(); clearKnownSession(); window.history.replaceState(null, '', '/') })
async function renderMfa() {
  render(<MfaVerification onBack={back} onAuthenticated={authenticated} />)
  const input = screen.getByLabelText('Verification code')
  await waitFor(() => expect(input).toBeEnabled())
  return input
}

describe('one MFA Verification page with five Figma states', () => {
  it('renders the approved default content and shared card styling', async () => {
    await renderMfa()
    expect(screen.getByRole('heading', { name: 'Verify your identity' })).toBeVisible()
    expect(screen.getByText('Enter the 6-digit code from your authenticator app.')).toBeVisible()
    expect(screen.getByPlaceholderText('Enter verification code')).toHaveValue('')
    expect(screen.getByRole('button', { name: 'Verify' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Back to Sign In' })).toBeEnabled()
    const form = screen.getByRole('heading').closest('form')!
    expect(getComputedStyle(form).width).toBe('480px')
    expect(getComputedStyle(form).maxWidth).toBe('100%')
    expect(getComputedStyle(form).padding).toBe('32px')
    expect(getComputedStyle(form).gap).toBe('24px')
    expect(screen.getByAltText('UPTIP')).toHaveAttribute('width', '108')
  })

  it('accepts six digits, preserves leading zeros, rejects other characters and overlength input', async () => {
    const input = await renderMfa()
    fireEvent.change(input, { target: { value: '00123' } })
    expect(screen.getByRole('button', { name: 'Verify' })).toBeDisabled()
    fireEvent.change(input, { target: { value: '001234' } })
    expect(input).toHaveValue('001234')
    expect(screen.getByRole('button', { name: 'Verify' })).toBeEnabled()
    expect(getComputedStyle(screen.getByRole('button', { name: 'Verify' })).backgroundColor).toBe('rgb(37, 99, 235)')
    for (const value of ['0012345', 'abcdef', '１２３４５６', '-12345']) {
      fireEvent.change(input, { target: { value } })
      expect(input).toHaveValue('001234')
    }
  })

  it('supports keyboard entry and numeric paste without storing the code', async () => {
    const input = await renderMfa()
    const user = userEvent.setup()
    await user.click(input)
    await user.paste('001234')
    expect(input).toHaveValue('001234')
    await user.clear(input)
    await user.type(input, '098765')
    expect(input).toHaveValue('098765')
    expect(JSON.stringify(sessionStorage)).not.toContain('098765')
    expect(JSON.stringify(localStorage)).not.toContain('098765')
  })

  it('preserves the submitted code and prevents duplicates in Verifying', async () => {
    let finish!: (value: unknown) => void
    verify.mockImplementation(() => new Promise((resolve) => { finish = resolve }))
    const input = await renderMfa()
    fireEvent.change(input, { target: { value: '001234' } })
    fireEvent.click(screen.getByRole('button', { name: 'Verify' }))
    expect(input).toBeDisabled()
    expect(input).toHaveValue('001234')
    expect(screen.getByRole('button', { name: 'Verifying...' })).toBeDisabled()
    fireEvent.submit(screen.getByRole('button', { name: 'Verifying...' }).closest('form')!)
    expect(verify).toHaveBeenCalledTimes(1)
    expect(verify).toHaveBeenCalledWith('/api/v1/auth/mfa/verify', expect.objectContaining({
      method: 'POST', credentials: 'same-origin', body: JSON.stringify({ code: '001234' }),
      headers: expect.objectContaining({ 'X-CSRF-Token': 'pending-csrf-fixture' }),
    }))
    await act(async () => { finish(response('invalid_code', 401)) })
  })

  it('shows Invalid Code in red, retains code, and dismisses only on editing', async () => {
    const input = await renderMfa()
    fireEvent.change(input, { target: { value: '001234' } })
    fireEvent.click(screen.getByRole('button', { name: 'Verify' }))
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('That code is incorrect. Check your authenticator app and try again.')
    expect(getComputedStyle(alert).backgroundColor).toBe('rgb(254, 242, 242)')
    expect(getComputedStyle(input).borderColor).toBe('rgb(220, 38, 38)')
    expect(input).toHaveValue('001234')
    fireEvent.focus(input)
    expect(alert).toBeVisible()
    fireEvent.change(input, { target: { value: '001235' } })
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('renders Code Expired only from backend outcome, clears input, dismisses when retyping', async () => {
    verify.mockResolvedValue(response('code_expired', 401))
    const input = await renderMfa()
    fireEvent.change(input, { target: { value: '001234' } })
    fireEvent.click(screen.getByRole('button', { name: 'Verify' }))
    const notice = await screen.findByRole('status')
    expect(notice).toHaveTextContent('This code has expired. Enter the latest code from your authenticator app.')
    expect(getComputedStyle(notice).backgroundColor).toBe('rgb(255, 251, 235)')
    expect(input).toHaveValue('')
    expect(screen.getByRole('button', { name: 'Verify' })).toBeDisabled()
    fireEvent.change(input, { target: { value: '0' } })
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
  })

  it('renders Too Many Attempts with disabled input/button and working Back', async () => {
    verify.mockResolvedValue(response('too_many_attempts', 429))
    const input = await renderMfa()
    fireEvent.change(input, { target: { value: '001234' } })
    fireEvent.click(screen.getByRole('button', { name: 'Verify' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Too many attempts. Try again in 15 minutes or contact your administrator.')
    expect(input).toBeDisabled()
    expect(input).toHaveValue('')
    expect(screen.getByRole('button', { name: 'Verify' })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: 'Back to Sign In' }))
    await waitFor(() => expect(back).toHaveBeenCalledTimes(1))
    expect(cancel).toHaveBeenCalledWith('/api/v1/auth/mfa/cancel', expect.objectContaining({ method: 'POST' }))
    expect(authenticated).not.toHaveBeenCalled()
  })

  it('keeps a backend lockout after reloading the page', async () => {
    fetcher.mockResolvedValue(response('too_many_attempts', 429))
    render(<MfaVerification onBack={back} onAuthenticated={authenticated} />)
    await screen.findByRole('alert')
    expect(screen.getByLabelText('Verification code')).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Back to Sign In' })).toBeEnabled()
  })

  it('handles network failures separately and allows retry', async () => {
    verify.mockRejectedValue(new TypeError('offline'))
    const input = await renderMfa()
    fireEvent.change(input, { target: { value: '001234' } })
    fireEvent.click(screen.getByRole('button', { name: 'Verify' }))
    expect(await screen.findByRole('status')).toHaveTextContent('Unable to reach the verification service. Please try again.')
    expect(screen.queryByText(/That code is incorrect/)).not.toBeInTheDocument()
    expect(input).toHaveValue('001234')
    expect(screen.getByRole('button', { name: 'Verify' })).toBeEnabled()
  })

  it('fails closed for expired or missing challenges', async () => {
    fetcher.mockResolvedValue(response('challenge_expired', 401))
    render(<MfaVerification onBack={back} onAuthenticated={authenticated} />)
    expect(await screen.findByRole('status')).toHaveTextContent('Your verification session has ended.')
    expect(screen.getByRole('button', { name: 'Verify' })).toBeDisabled()
    expect(authenticated).not.toHaveBeenCalled()
  })

  it('does not leave the flow if backend cancellation fails', async () => {
    cancel.mockRejectedValue(new TypeError('offline'))
    await renderMfa()
    fireEvent.click(screen.getByRole('button', { name: 'Back to Sign In' }))
    expect(await screen.findByRole('status')).toHaveTextContent('Unable to cancel verification.')
    expect(back).not.toHaveBeenCalled()
  })

  it('suppresses an obsolete verification response after cancellation', async () => {
    let finish!: (value: unknown) => void
    verify.mockImplementation(() => new Promise((resolve) => { finish = resolve }))
    const input = await renderMfa()
    fireEvent.change(input, { target: { value: '001234' } })
    fireEvent.click(screen.getByRole('button', { name: 'Verify' }))
    fireEvent.click(screen.getByRole('button', { name: 'Back to Sign In' }))
    await waitFor(() => expect(back).toHaveBeenCalled())
    await act(async () => { finish(response('authenticated')) })
    expect(authenticated).not.toHaveBeenCalled()
  })

  it('integrates Login -> MFA -> real response -> existing success notice without dashboard navigation', async () => {
    verify.mockImplementation(async () => { sessionAuthenticated = true; return response('authenticated') })
    render(<App />)
    const user = userEvent.setup()
    await user.type(screen.getByLabelText('Username'), 'dedicated-test-user')
    await user.type(screen.getByLabelText('Password'), 'supplied-password')
    await user.click(screen.getByRole('button', { name: 'Sign In' }))
    await screen.findByRole('heading', { name: 'Verify your identity' })
    expect(window.location.pathname).toBe('/mfa')
    const input = screen.getByLabelText('Verification code')
    await waitFor(() => expect(input).toBeEnabled())
    await user.type(input, '001234')
    await user.click(screen.getByRole('button', { name: 'Verify' }))
    expect(await screen.findByText('Authentication complete.')).toBeVisible()
    expect(window.location.pathname).toBe('/')
    expect(screen.getByRole('heading', { name: 'Sign in to UPTIP' })).toBeVisible()
  })
})
