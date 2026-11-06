/// <reference types="node" />
import { readFileSync } from 'node:fs'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import FirstLogin from './FirstLogin'
import App from '../App'
import { passwordMeetsRequirements } from '../services/password'
import { clearKnownSession } from '../services/auth'

const style = document.createElement('style')
beforeAll(() => {
  style.textContent = readFileSync('src/components/Login.css', 'utf8') + readFileSync('src/components/FirstLogin.css', 'utf8')
  document.head.append(style)
})
afterAll(() => style.remove())
const reply = (state: string, status = 200, next = true) => ({ ok: status < 400, status,
  json: async () => ({ state, next_step_available: next, csrf_token: state === 'password_changed' ? null : 'password-csrf-fixture', message: 'Rejected password.' }) })
const changed = vi.fn()
const ended = vi.fn()
let replacement = vi.fn<(...args: unknown[]) => Promise<unknown>>()
let challenge = vi.fn<(...args: unknown[]) => Promise<unknown>>()
let fetcher = vi.fn<(...args: unknown[]) => Promise<unknown>>()
beforeEach(() => {
  changed.mockReset(); ended.mockReset(); clearKnownSession()
  window.history.replaceState(null, '', '/')
  replacement = vi.fn().mockResolvedValue(reply('password_changed'))
  challenge = vi.fn().mockResolvedValue(reply('password_change_required'))
  fetcher = vi.fn((...args) => {
    if (args[0] === '/api/v1/auth/password/change') return replacement(...args)
    if (args[0] === '/api/v1/auth/password/challenge') return challenge(...args)
    if (args[0] === '/api/v1/auth/login') return Promise.resolve(reply('password_change_required'))
    return Promise.resolve(reply('unauthenticated', 401, false))
  })
  vi.stubGlobal('fetch', fetcher)
})
afterEach(() => { vi.unstubAllGlobals(); clearKnownSession(); window.history.replaceState(null, '', '/') })
async function show() {
  render(<FirstLogin onChanged={changed} onSessionEnded={ended} />)
  await waitFor(() => expect(screen.getByLabelText('New password')).toBeEnabled())
}
function enter(password = 'ReplacementPassword456!', confirmation = password) {
  fireEvent.change(screen.getByLabelText('New password'), { target: { value: password } })
  fireEvent.change(screen.getByLabelText('Confirm new password'), { target: { value: confirmation } })
}

describe('First Login Figma states and restricted flow', () => {
  it('renders the default layout, approved wording and disabled action', async () => {
    await show()
    expect(screen.getByRole('heading', { name: 'Set a new password' })).toBeVisible()
    expect(screen.getByText('Your account uses a temporary password. Create a new one to continue.')).toBeVisible()
    expect(screen.getByText('Use at least 12 characters, with upper and lower case letters, a number and a symbol.')).toBeVisible()
    expect(screen.getByRole('button', { name: 'Set new password' })).toBeDisabled()
    expect(screen.getByLabelText('New password')).toHaveAttribute('type', 'password')
    expect(screen.getByLabelText('Confirm new password')).toHaveAttribute('type', 'password')
    const form = screen.getByRole('heading').closest('form')!
    expect(getComputedStyle(form).width).toBe('480px')
    expect(getComputedStyle(form).padding).toBe('32px')
    expect(getComputedStyle(form).maxWidth).toBe('100%')
  })

  it('supports independent password visibility toggles without changing values', async () => {
    await show()
    enter()
    const user = userEvent.setup()
    const newPassword = screen.getByLabelText('New password')
    const confirmation = screen.getByLabelText('Confirm new password')
    await user.click(screen.getByRole('button', { name: 'Show new password' }))
    expect(newPassword).toHaveAttribute('type', 'text')
    expect(confirmation).toHaveAttribute('type', 'password')
    await user.click(screen.getByRole('button', { name: 'Show confirm new password' }))
    expect(confirmation).toHaveAttribute('type', 'text')
    await user.click(screen.getByRole('button', { name: 'Hide new password' }))
    expect(newPassword).toHaveAttribute('type', 'password')
    expect(confirmation).toHaveAttribute('type', 'text')
    expect(newPassword).toHaveValue('ReplacementPassword456!')
    expect(confirmation).toHaveValue('ReplacementPassword456!')
    expect(replacement).not.toHaveBeenCalled()
  })

  it.each(['Short1!', 'lowercaseonly123!', 'UPPERCASEONLY123!', 'NoNumbersHere!!', 'NoSymbolsHere123'])(
    'disables submit for an unmet password requirement: %s', async (password) => {
      await show()
      enter(password)
      expect(passwordMeetsRequirements(password)).toBe(false)
      expect(screen.getByRole('button', { name: 'Set new password' })).toBeDisabled()
      fireEvent.submit(screen.getByRole('button', { name: 'Set new password' }).closest('form')!)
      expect(replacement).not.toHaveBeenCalled()
    })

  it('shows the exact red mismatch state on confirmation blur and preserves the new password', async () => {
    await show()
    enter('ReplacementPassword456!', 'DifferentPassword789!')
    fireEvent.blur(screen.getByLabelText('Confirm new password'))
    const alert = screen.getByRole('alert')
    expect(alert).toHaveTextContent('Passwords do not match. Re-enter your new password.')
    expect(getComputedStyle(alert).backgroundColor).toBe('rgb(254, 242, 242)')
    expect(screen.getByLabelText('New password')).toHaveValue('ReplacementPassword456!')
    expect(screen.getByRole('button', { name: 'Set new password' })).toBeDisabled()
    fireEvent.change(screen.getByLabelText('Confirm new password'), { target: { value: 'ReplacementPassword456!' } })
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Set new password' })).toBeEnabled()
  })

  it('submits the actual payload once, disables controls and handles success without authentication', async () => {
    let finish!: (value: unknown) => void
    replacement.mockImplementation(() => new Promise((resolve) => { finish = resolve }))
    await show()
    enter()
    fireEvent.click(screen.getByRole('button', { name: 'Set new password' }))
    expect(screen.getByLabelText('New password')).toBeDisabled()
    fireEvent.submit(screen.getByRole('button', { name: 'Set new password' }).closest('form')!)
    expect(replacement).toHaveBeenCalledTimes(1)
    expect(replacement).toHaveBeenCalledWith('/api/v1/auth/password/change', expect.objectContaining({
      method: 'POST', credentials: 'same-origin', headers: expect.objectContaining({ 'X-CSRF-Token': 'password-csrf-fixture' }),
      body: JSON.stringify({ new_password: 'ReplacementPassword456!', confirmation: 'ReplacementPassword456!' }),
    }))
    await act(async () => { finish(reply('password_changed')) })
    expect(changed).toHaveBeenCalledTimes(1)
    expect(screen.getByLabelText('New password')).toHaveValue('')
    expect(screen.getByLabelText('Confirm new password')).toHaveValue('')
    expect(screen.queryByText('Authentication complete.')).not.toBeInTheDocument()
  })

  it('handles a server mismatch and preserves entered values', async () => {
    replacement.mockResolvedValue(reply('password_mismatch', 422))
    await show()
    enter()
    fireEvent.click(screen.getByRole('button', { name: 'Set new password' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Passwords do not match. Re-enter your new password.')
    expect(screen.getByLabelText('New password')).toHaveValue('ReplacementPassword456!')
  })

  it('handles a network failure without losing passwords or claiming completion', async () => {
    replacement.mockRejectedValue(new TypeError('offline'))
    await show()
    enter()
    fireEvent.click(screen.getByRole('button', { name: 'Set new password' }))
    expect(await screen.findByRole('status')).toHaveTextContent('Unable to reach the password service.')
    expect(screen.getByLabelText('New password')).toHaveValue('ReplacementPassword456!')
    expect(changed).not.toHaveBeenCalled()
  })

  it('returns to Login when a submitted challenge expires', async () => {
    replacement.mockResolvedValue(reply('challenge_expired', 401, false))
    await show()
    enter()
    fireEvent.click(screen.getByRole('button', { name: 'Set new password' }))
    await waitFor(() => expect(ended).toHaveBeenCalledTimes(1))
    expect(changed).not.toHaveBeenCalled()
  })

  it('rejects an invalid direct-route challenge', async () => {
    window.history.replaceState(null, '', '/first-login')
    challenge.mockResolvedValue(reply('challenge_expired', 401, false))
    render(<App />)
    await screen.findByRole('heading', { name: 'Sign in to UPTIP' })
    expect(window.location.pathname).toBe('/')
    expect(replacement).not.toHaveBeenCalled()
  })

  it('navigates Login -> First Login only with a usable backend response and returns for fresh login', async () => {
    render(<App />)
    const user = userEvent.setup()
    await user.type(screen.getByLabelText('Username'), 'temporary-test-user')
    await user.type(screen.getByLabelText('Password'), 'temporary-test-password')
    await user.click(screen.getByRole('button', { name: 'Sign In' }))
    await screen.findByRole('heading', { name: 'Set a new password' })
    expect(window.location.pathname).toBe('/first-login')
    await waitFor(() => expect(screen.getByLabelText('New password')).toBeEnabled())
    enter()
    await user.click(screen.getByRole('button', { name: 'Set new password' }))
    await screen.findByRole('heading', { name: 'Sign in to UPTIP' })
    expect(screen.getByLabelText('Username')).toHaveValue('')
    expect(screen.getByLabelText('Password')).toHaveValue('')
    expect(screen.queryByText('Authentication complete.')).not.toBeInTheDocument()
    fetcher.mockImplementation((...args) => args[0] === '/api/v1/auth/login'
      ? Promise.resolve(reply('authenticated', 200, false))
      : Promise.resolve(reply('unauthenticated', 401, false)))
    await user.type(screen.getByLabelText('Username'), 'temporary-test-user')
    await user.type(screen.getByLabelText('Password'), 'ReplacementPassword456!')
    await user.click(screen.getByRole('button', { name: 'Sign In' }))
    expect(await screen.findByText('Authentication complete.')).toBeVisible()
    expect(window.location.pathname).toBe('/')
    expect(fetcher.mock.calls.every(([url]) => ['/api/v1/auth/login', '/api/v1/auth/session',
      '/api/v1/auth/password/challenge', '/api/v1/auth/password/change'].includes(String(url)))).toBe(true)
  })

  it('does not enable password replacement from a response state alone', async () => {
    challenge.mockResolvedValue(reply('password_change_required', 200, false))
    render(<FirstLogin onChanged={changed} onSessionEnded={ended} />)
    await screen.findByRole('status')
    expect(screen.getByLabelText('New password')).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Set new password' })).toBeDisabled()
  })
})
