import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import App from './App'
import { assessmentId, testingData } from './test-fixtures/testing'

const path = '/analyst/assessments/' + assessmentId + '/testing'
const reply = (value: unknown, status = 200) => ({ ok: status < 400, status, json: async () => value })
afterEach(() => { cleanup(); vi.unstubAllGlobals(); window.history.replaceState(null, '', '/') })

it('restores an authenticated direct Testing URL and survives a full remount', async () => {
  window.history.replaceState(null, '', path)
  const fetcher = vi.fn(async (input: RequestInfo | URL) => reply(String(input).endsWith('/session')
    ? { state: 'authenticated', user_id: 'synthetic-analyst', username: 'analyst', role: 'Security Analyst', csrf_token: 'synthetic-csrf' }
    : testingData(['Queued'])))
  vi.stubGlobal('fetch', fetcher)
  const view = render(<App />)
  expect(screen.queryByRole('table')).not.toBeInTheDocument()
  expect(await screen.findByRole('heading', { name: 'Testing' })).toBeVisible()
  expect(await screen.findByRole('table')).toBeVisible()
  expect(window.location.pathname).toBe(path)
  expect(screen.getByRole('link', { name: 'Testing' })).toHaveAttribute('aria-current', 'page')
  view.unmount()
  render(<App />)
  expect(await screen.findByRole('table')).toBeVisible()
  expect(window.location.pathname).toBe(path)
})

it('clears the previous analyst Testing view when session identity changes', async () => {
  window.history.replaceState(null, '', path)
  let changed = false
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => String(input).endsWith('/session')
    ? reply({ state: 'authenticated', user_id: changed ? 'synthetic-b' : 'synthetic-a', username: 'analyst', role: 'Security Analyst', csrf_token: 'synthetic-csrf' })
    : changed ? reply({}, 404) : reply(testingData(['Queued']))))
  render(<App />)
  expect(await screen.findByRole('table')).toBeVisible()
  changed = true
  fireEvent.focus(window)
  expect(await screen.findByRole('alert')).toHaveTextContent('Assessment unavailable')
  expect(screen.queryByText('192.0.2.1')).not.toBeInTheDocument()
})

it.each(['unauthenticated', 'session_expired'])('protects a direct Testing URL for %s', async state => {
  window.history.replaceState(null, '', path)
  const fetcher = vi.fn<(input: RequestInfo | URL) => Promise<ReturnType<typeof reply>>>().mockResolvedValue(reply({ state }, 401))
  vi.stubGlobal('fetch', fetcher)
  render(<App />)
  expect(await screen.findByRole('heading', { name: 'Sign in to UPTIP' })).toBeVisible()
  expect(screen.queryByRole('table')).not.toBeInTheDocument()
  expect(fetcher.mock.calls.every(([url]) => !String(url).endsWith('/testing'))).toBe(true)
})

it('keeps a Technical Administrator out of the analyst Testing route', async () => {
  window.history.replaceState(null, '', path)
  vi.stubGlobal('fetch', vi.fn(async () => reply({ state: 'authenticated', role: 'Technical Administrator', csrf_token: 'synthetic-csrf' })))
  render(<App />)
  expect(await screen.findByRole('heading', { name: 'Administrator Dashboard' })).toBeVisible()
  expect(window.location.pathname).toBe('/admin/dashboard')
  expect(screen.queryByRole('heading', { name: 'Testing' })).not.toBeInTheDocument()
})
