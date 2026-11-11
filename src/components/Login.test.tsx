/// <reference types="node" />
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { clearKnownSession, rememberSession } from '../services/auth'
import Login from './Login'
import { readFileSync } from 'node:fs'
const loginCss = readFileSync('src/components/Login.css', 'utf8')

const styles = document.createElement('style')
beforeAll(() => { styles.textContent = loginCss; document.head.append(styles) })
afterAll(() => styles.remove())

const reply = (state: string, status = 200) => ({
  ok: status < 400, status,
  json: async () => ({ state, next_step_available: false, csrf_token: null }),
})
let sessionState: string
let sessionStatus: number
let post = vi.fn<(url: string, options?: RequestInit) => Promise<unknown>>()
beforeEach(() => {
  clearKnownSession()
  sessionState = 'unauthenticated'
  sessionStatus = 401
  post = vi.fn().mockResolvedValue(reply('invalid_credentials', 401))
  vi.stubGlobal('fetch', vi.fn((url: string, options?: RequestInit) => {
    if (url === '/api/v1/auth/session') return Promise.resolve(reply(sessionState, sessionStatus))
    return post(url, options)
  }))
})
afterEach(() => { clearKnownSession(); vi.unstubAllGlobals() })

async function fill() {
  const user = userEvent.setup()
  await user.type(screen.getByLabelText('Username'), 'analyst-01')
  await user.type(screen.getByLabelText('Password'), 'test-password')
  return user
}

describe('Figma Login scenarios', () => {
  it('renders Default with empty fields, disabled submit, and no session notice', async () => {
    render(<Login />)
    expect(screen.getByRole('heading', { name: 'Sign in to UPTIP' })).toBeVisible()
    expect(screen.getByLabelText('Username')).toHaveValue('')
    expect(screen.getByLabelText('Password')).toHaveAttribute('type', 'password')
    expect(screen.getByRole('button', { name: 'Sign In' })).toBeDisabled()
    fireEvent.submit(screen.getByRole('button', { name: 'Sign In' }).closest('form')!)
    expect(post).not.toHaveBeenCalled()
    await act(async () => {})
    expect(screen.queryByText('Your session has ended. Sign in again to continue.')).not.toBeInTheDocument()
  })

  it('immediately enables Filled/Ready only with both values and disables when either is cleared', async () => {
    render(<Login />)
    const user = userEvent.setup()
    const button = screen.getByRole('button', { name: 'Sign In' })
    expect(getComputedStyle(button).backgroundColor).toBe('rgb(241, 245, 249)')
    await user.type(screen.getByLabelText('Username'), 'analyst-01')
    expect(button).toBeDisabled()
    await user.type(screen.getByLabelText('Password'), 'secret')
    expect(button).toBeEnabled()
    expect(button).toHaveAttribute('data-state', 'ready')
    expect(getComputedStyle(button).backgroundColor).toBe('rgb(37, 99, 235)')
    expect(getComputedStyle(button).color).toBe('rgb(255, 255, 255)')
    await user.clear(screen.getByLabelText('Username'))
    expect(button).toBeDisabled()
    await user.type(screen.getByLabelText('Username'), '   ')
    expect(button).toBeDisabled()
  })

  it('toggles the actual password type and icon in both directions without changing its value or submitting', async () => {
    render(<Login />)
    const user = await fill()
    const input = screen.getByLabelText('Password')
    const hiddenIcon = screen.getByRole('button', { name: 'Show password' }).querySelector('img')!.getAttribute('src')
    await user.click(screen.getByRole('button', { name: 'Show password' }))
    expect(input).toHaveAttribute('type', 'text')
    expect(input).toHaveValue('test-password')
    const hide = screen.getByRole('button', { name: 'Hide password' })
    expect(hide).toHaveAttribute('aria-pressed', 'true')
    expect(hide.querySelector('img')!.getAttribute('src')).not.toBe(hiddenIcon)
    await user.click(hide)
    expect(input).toHaveAttribute('type', 'password')
    expect(input).toHaveValue('test-password')
    expect(screen.getByRole('button', { name: 'Show password' }).querySelector('img')).toHaveAttribute('src', hiddenIcon!)
    expect(post).not.toHaveBeenCalled()
  })

  it('supports keyboard password visibility activation', async () => {
    render(<Login />)
    const user = await fill()
    screen.getByRole('button', { name: 'Show password' }).focus()
    await user.keyboard('{Enter}')
    expect(screen.getByLabelText('Password')).toHaveAttribute('type', 'text')
    await user.keyboard(' ')
    expect(screen.getByLabelText('Password')).toHaveAttribute('type', 'password')
  })

  it('disables all controls while Signing In, masks the password, and blocks duplicate submits', async () => {
    let finish!: (value: unknown) => void
    post.mockImplementation(() => new Promise((resolve) => { finish = resolve }))
    render(<Login />)
    const user = await fill()
    await user.click(screen.getByRole('button', { name: 'Show password' }))
    await user.click(screen.getByRole('button', { name: 'Sign In' }))
    expect(screen.getByRole('button', { name: 'Signing in...' })).toBeDisabled()
    expect(screen.getByLabelText('Username')).toBeDisabled()
    expect(screen.getByLabelText('Password')).toBeDisabled()
    expect(screen.getByLabelText('Password')).toHaveAttribute('type', 'password')
    expect(screen.getByRole('button', { name: 'Show password' })).toBeDisabled()
    fireEvent.submit(screen.getByRole('button', { name: 'Signing in...' }).closest('form')!)
    expect(post).toHaveBeenCalledTimes(1)
    expect(post).toHaveBeenCalledWith('/api/v1/auth/login', expect.objectContaining({
      method: 'POST', credentials: 'same-origin',
      body: JSON.stringify({ username: 'analyst-01', password: 'test-password' }),
    }))
    finish(reply('invalid_credentials', 401))
    await screen.findByRole('alert')
    expect(screen.getByRole('button', { name: 'Sign In' })).toBeEnabled()
  })

  it('shows Invalid Credentials above fields, retains values, and restores active button', async () => {
    render(<Login />)
    const user = await fill()
    await user.click(screen.getByRole('button', { name: 'Sign In' }))
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('Unable to sign in. Check your credentials and try again.')
    expect(alert).toHaveClass('login-alert--error')
    expect(getComputedStyle(alert).backgroundColor).toBe('rgb(254, 242, 242)')
    expect(getComputedStyle(alert).color).toBe('rgb(153, 27, 27)')
    expect(alert.compareDocumentPosition(screen.getByLabelText('Username')) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(screen.getByLabelText('Username')).toHaveValue('analyst-01')
    expect(screen.getByLabelText('Password')).toHaveValue('test-password')
    expect(screen.getByRole('button', { name: 'Sign In' })).toBeEnabled()
  })

  it('shows Account Unavailable info alert, keeps username, clears password, and disables submit', async () => {
    post.mockResolvedValue(reply('account_unavailable', 403))
    render(<Login />)
    const user = await fill()
    await user.click(screen.getByRole('button', { name: 'Sign In' }))
    const alert = await screen.findByRole('status')
    expect(alert).toHaveTextContent('Your account is currently unavailable. Contact your administrator.')
    expect(alert).toHaveClass('login-alert--info')
    expect(screen.getByLabelText('Username')).toHaveValue('analyst-01')
    expect(screen.getByLabelText('Password')).toHaveValue('')
    expect(screen.getByRole('button', { name: 'Sign In' })).toBeDisabled()
  })

  it('shows the Caps Lock text below password without adding an icon, and clears when off', async () => {
    render(<Login />)
    const user = await fill()
    const input = screen.getByLabelText('Password')
    fireEvent.keyDown(input, { key: 'A', modifierCapsLock: true })
    const warning = screen.getByText('Caps Lock is on')
    expect(warning).toHaveClass('login-caps-lock')
    expect(warning.querySelector('img')).toBeNull()
    expect(input).toHaveAttribute('aria-describedby', 'login-caps-lock')
    expect(input.compareDocumentPosition(warning) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Sign In' })).toBeEnabled()
    fireEvent.keyUp(input, { key: 'CapsLock', modifierCapsLock: false })
    expect(screen.queryByText('Caps Lock is on')).not.toBeInTheDocument()
    await user.click(document.body)
  })

  it('shows Session Expired after a previously observed session disappears, with empty fields', async () => {
    rememberSession()
    render(<Login />)
    expect(await screen.findByRole('status')).toHaveTextContent('Your session has ended. Sign in again to continue.')
    expect(screen.getByLabelText('Username')).toHaveValue('')
    expect(screen.getByLabelText('Password')).toHaveValue('')
    expect(screen.getByRole('button', { name: 'Sign In' })).toBeDisabled()
  })

  it('honors a server-verified expired session without a browser hint', async () => {
    sessionState = 'session_expired'
    render(<Login />)
    expect(await screen.findByRole('status')).toHaveTextContent('Your session has ended. Sign in again to continue.')
  })

  it('detects expiry on focus after observing an authenticated session', async () => {
    sessionState = 'authenticated'
    sessionStatus = 200
    render(<Login />)
    await waitFor(() => expect(sessionStorage.getItem('uptip.previously-authenticated')).toBe('true'))
    sessionState = 'unauthenticated'
    sessionStatus = 401
    fireEvent.focus(window)
    expect(await screen.findByRole('status')).toHaveTextContent('Your session has ended. Sign in again to continue.')
  })

  it('does not confuse session-network failures with expiry', async () => {
    rememberSession()
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('offline')))
    render(<Login />)
    await act(async () => {})
    expect(screen.queryByText('Your session has ended. Sign in again to continue.')).not.toBeInTheDocument()
  })

  it('handles network failures, preserves input for retry and restores active button', async () => {
    post.mockRejectedValue(new TypeError('offline'))
    render(<Login />)
    const user = await fill()
    await user.click(screen.getByRole('button', { name: 'Sign In' }))
    expect(await screen.findByRole('status')).toHaveTextContent('Unable to reach the sign-in service.')
    expect(screen.getByLabelText('Password')).toHaveValue('test-password')
    expect(screen.getByRole('button', { name: 'Sign In' })).toBeEnabled()
  })

  it.each(['password_change_required'])(
    'does not claim completion or navigate for %s', async (state) => {
      const href = window.location.href
      post.mockResolvedValue(reply(state))
      render(<Login />)
      const user = await fill()
      await user.click(screen.getByRole('button', { name: 'Sign In' }))
      expect(await screen.findByRole('status')).toHaveTextContent('not yet available')
      expect(window.location.href).toBe(href)
      expect(screen.queryByText('Authentication complete.')).not.toBeInTheDocument()
    })

  it.each([
    ['authenticated', 'Authentication complete.'],
    ['unavailable', 'Sign-in is temporarily unavailable. Please try again.'],
    ['rate_limited', 'Too many sign-in attempts. Please try again later.'],
  ])('handles %s without navigation', async (state, message) => {
    const href = window.location.href
    post.mockResolvedValue(reply(state, state === 'authenticated' ? 200 : 503))
    render(<Login />)
    const user = await fill()
    await user.click(screen.getByRole('button', { name: 'Sign In' }))
    expect(await screen.findByRole('status')).toHaveTextContent(message)
    expect(window.location.href).toBe(href)
  })
})

describe('Approved Login message dismissal', () => {
  it.each([
    ['invalid_credentials', 'Username'], ['invalid_credentials', 'Password'],
    ['account_unavailable', 'Username'], ['account_unavailable', 'Password'],
    ['session_expired', 'Username'], ['session_expired', 'Password'],
  ])('clears %s immediately when %s changes', async (state, field) => {
    if (state === 'session_expired') {
      sessionState = 'session_expired'
      render(<Login />)
      await screen.findByText('Your session has ended. Sign in again to continue.')
      sessionState = 'unauthenticated' // Real endpoint removes the expired cookie.
    } else {
      post.mockResolvedValue(reply(state, state === 'account_unavailable' ? 403 : 401))
      render(<Login />)
      const user = await fill()
      await user.click(screen.getByRole('button', { name: 'Sign In' }))
      await screen.findByRole(state === 'invalid_credentials' ? 'alert' : 'status')
    }
    const usernameBefore = (screen.getByLabelText('Username') as HTMLInputElement).value
    const input = screen.getByLabelText(field)
    fireEvent.change(input, { target: { value: field === 'Username' ? 'corrected-user' : 'new-password' } })
    expect(document.getElementById('login-notice')).toBeNull()
    expect(post).toHaveBeenCalledTimes(state === 'session_expired' ? 0 : 1)
    if (state === 'account_unavailable' && field === 'Password') {
      expect(screen.getByLabelText('Username')).toHaveValue(usernameBefore)
      expect(screen.getByRole('button', { name: 'Sign In' })).toBeEnabled()
    }
  })

  it('displays Invalid Credentials again if a corrected attempt also fails', async () => {
    render(<Login />)
    const user = await fill()
    await user.click(screen.getByRole('button', { name: 'Sign In' }))
    await screen.findByRole('alert')
    await user.type(screen.getByLabelText('Password'), 'correction')
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Sign In' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Unable to sign in. Check your credentials and try again.')
    expect(post).toHaveBeenCalledTimes(2)
  })

  it.each(['invalid_credentials', 'account_unavailable', 'session_expired', 'authenticated'])(
    'keeps %s visible while idle, without timer dismissal', async (state) => {
      vi.useFakeTimers()
      try {
        if (state === 'session_expired') sessionState = 'session_expired'
        post.mockResolvedValue(reply(state, state === 'invalid_credentials' ? 401 : state === 'account_unavailable' ? 403 : 200))
        render(<Login />)
        await act(async () => {})
        if (state !== 'session_expired') {
          fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'analyst-01' } })
          fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'test-password' } })
          await act(async () => { fireEvent.submit(screen.getByRole('button', { name: 'Sign In' }).closest('form')!) })
        }
        const notice = document.getElementById('login-notice')!
        expect(notice).not.toBeNull()
        const message = notice.textContent
        sessionState = state === 'authenticated' ? 'authenticated' : 'unauthenticated'
        sessionStatus = state === 'authenticated' ? 200 : 401
        await act(async () => { await vi.advanceTimersByTimeAsync(5 * 60 * 1000) })
        expect(document.getElementById('login-notice')).toHaveTextContent(message!)
      } finally {
        vi.useRealTimers()
      }
    })

  it('keeps Authentication Complete when either credential is edited', async () => {
    post.mockResolvedValue(reply('authenticated'))
    render(<Login />)
    const user = await fill()
    await user.click(screen.getByRole('button', { name: 'Sign In' }))
    await screen.findByText('Authentication complete.')
    await user.type(screen.getByLabelText('Username'), '-edited')
    await user.type(screen.getByLabelText('Password'), 'another-password')
    expect(screen.getByRole('status')).toHaveTextContent('Authentication complete.')
    expect(post).toHaveBeenCalledTimes(1)
  })

  it('does not clear Invalid Credentials on focus or password visibility changes', async () => {
    render(<Login />)
    const user = await fill()
    await user.click(screen.getByRole('button', { name: 'Sign In' }))
    await screen.findByRole('alert')
    await user.click(screen.getByLabelText('Username'))
    await user.click(screen.getByRole('button', { name: 'Show password' }))
    expect(screen.getByRole('alert')).toHaveTextContent('Unable to sign in. Check your credentials and try again.')
    expect(screen.getByLabelText('Password')).toHaveValue('test-password')
    expect(screen.getByLabelText('Password')).toHaveAttribute('type', 'text')
  })

  it('does not restore a dismissed expiry notice from an older session check', async () => {
    let finish!: (value: unknown) => void
    let reads = 0
    vi.stubGlobal('fetch', vi.fn((url: string) => {
      if (url === '/api/v1/auth/session') {
        reads += 1
        return reads === 1 ? Promise.resolve(reply('session_expired', 401)) : new Promise((resolve) => { finish = resolve })
      }
      return Promise.resolve(reply('authenticated'))
    }))
    render(<Login />)
    await screen.findByText('Your session has ended. Sign in again to continue.')
    fireEvent.focus(window)
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'corrected-user' } })
    expect(document.getElementById('login-notice')).toBeNull()
    await act(async () => { finish(reply('session_expired', 401)) })
    expect(document.getElementById('login-notice')).toBeNull()
    expect(screen.getByLabelText('Username')).toHaveValue('corrected-user')
  })
})
