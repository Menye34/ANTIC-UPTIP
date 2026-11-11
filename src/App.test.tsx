import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App'
import { clearKnownSession } from './services/auth'

function reply(state: string, status = 200, role?: string) {
  return { ok: status < 400, status, json: async () => ({
    state, role, csrf_token: state === 'authenticated' ? 'session-csrf-fixture' : null,
  }) }
}

const roles = [
  ['Security Analyst', '/analyst/dashboard', 'Dashboard', '/admin/dashboard'],
  ['Technical Administrator', '/admin/dashboard', 'Administrator Dashboard', '/analyst/dashboard'],
] as const

beforeEach(() => {
  window.history.replaceState(null, '', '/')
  clearKnownSession()
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  clearKnownSession()
})

describe('Workspace session routing', () => {
  it.each(roles)('routes %s after password login', async (role, path, title) => {
    let authenticated = false
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      if (url === '/api/v1/auth/login') authenticated = true
      return authenticated ? reply('authenticated', 200, role) : reply('unauthenticated', 401)
    }))
    render(<App />)
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'fixture-user' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'fixture-password' } })
    fireEvent.click(screen.getByRole('button', { name: 'Sign In' }))
    expect(await screen.findByRole('heading', { name: title })).toBeVisible()
    expect(window.location.pathname).toBe(path)
  })

  it.each(roles)('restores %s on refresh and redirects a cross-role URL', async (role, path, title, otherPath) => {
    window.history.replaceState(null, '', otherPath)
    vi.stubGlobal('fetch', vi.fn(async () => reply('authenticated', 200, role)))
    const view = render(<App />)
    expect(screen.getByRole('status')).toHaveTextContent('Checking your session')
    expect(screen.queryByRole('heading')).not.toBeInTheDocument()
    expect(await screen.findByRole('heading', { name: title })).toBeVisible()
    expect(window.location.pathname).toBe(path)
    view.unmount()
    clearKnownSession()
    render(<App />)
    expect(await screen.findByRole('heading', { name: title })).toBeVisible()
  })

  it.each(roles)('signs out %s after refresh using the restored CSRF token', async (role, path) => {
    window.history.replaceState(null, '', path)
    let authenticated = true
    const fetcher = vi.fn(async (url: string) => {
      if (url === '/api/v1/auth/logout') {
        authenticated = false
        return reply('unauthenticated')
      }
      return authenticated ? reply('authenticated', 200, role) : reply('unauthenticated', 401)
    })
    vi.stubGlobal('fetch', fetcher)
    render(<App />)
    if (role === 'Security Analyst') fireEvent.click(await screen.findByRole('button', { name: 'Account' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Sign Out' }))
    expect(await screen.findByRole('heading', { name: 'Sign in to UPTIP' })).toBeVisible()
    expect(fetcher).toHaveBeenCalledWith('/api/v1/auth/logout', expect.objectContaining({
      method: 'POST', credentials: 'same-origin', headers: { 'X-CSRF-Token': 'session-csrf-fixture' },
    }))
    expect(window.location.pathname).toBe('/')
    expect(sessionStorage.getItem('uptip.previously-authenticated')).toBeNull()
  })

  it.each(['unauthenticated', 'session_expired'])('returns direct access to Login for %s', async (state) => {
    window.history.replaceState(null, '', '/admin/dashboard')
    vi.stubGlobal('fetch', vi.fn(async () => reply(state, 401)))
    render(<App />)
    expect(await screen.findByRole('heading', { name: 'Sign in to UPTIP' })).toBeVisible()
    expect(window.location.pathname).toBe('/')
    if (state === 'session_expired') expect(screen.getByText('Your session has ended. Sign in again to continue.')).toBeVisible()
  })

  it('denies a workspace for an unknown role', async () => {
    window.history.replaceState(null, '', '/analyst/dashboard')
    vi.stubGlobal('fetch', vi.fn(async () => reply('authenticated', 200, 'Other role')))
    render(<App />)
    expect(await screen.findByRole('heading', { name: 'Workspace access unavailable' })).toBeVisible()
    expect(screen.queryByRole('heading', { name: /dashboard/i })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Sign Out' })).toBeEnabled()
  })

  it('blocks dashboard content during an outage and verifies again on retry', async () => {
    window.history.replaceState(null, '', '/analyst/dashboard')
    const fetcher = vi.fn().mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValue(reply('authenticated', 200, 'Security Analyst'))
    vi.stubGlobal('fetch', fetcher)
    render(<App />)
    expect(await screen.findByRole('alert')).toHaveTextContent('temporarily unavailable')
    expect(window.location.pathname).toBe('/analyst/dashboard')
    expect(screen.queryByRole('heading')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Dashboard' })).toBeVisible())
  })
})
