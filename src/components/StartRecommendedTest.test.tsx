import { useState } from 'react'
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import StartRecommendedTest from './StartRecommendedTest'
import { assessmentId, intelligentRecommendationData } from '../test-fixtures/testing'

const recommendation = intelligentRecommendationData('Accepted').recommendations[0]
const ready = { assessment_id: assessmentId, recommendation_id: recommendation.id, ready: true,
  reason_code: 'ready', snapshot_digest: 'b'.repeat(64), configured_profile: 'Web Server Security Checks',
  endpoint: `https://${recommendation.target}:443/` }
const receipt = { id: 'synthetic-job', assessment_id: assessmentId, recommendation_id: recommendation.id,
  status: 'Queued', tool: 'Nikto', already_requested: false, execution_authorized: false }
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })
const started = vi.fn(), closed = vi.fn(), expired = vi.fn()
function Wrapper() {
  const [operation, onOperationChange] = useState<'idle' | 'uncertain' | 'confirmed'>('idle')
  return <StartRecommendedTest assessmentId={assessmentId} recommendation={recommendation} csrfToken="test-csrf"
    operation={operation} onOperationChange={onOperationChange} onStarted={started} onClose={closed} onExpired={expired} />
}
beforeEach(() => {
  started.mockReset(); closed.mockReset(); expired.mockReset()
  Object.defineProperty(HTMLDialogElement.prototype, 'showModal', { configurable: true, value(this: HTMLDialogElement) { this.open = true } })
  Object.defineProperty(HTMLDialogElement.prototype, 'close', { configurable: true, value(this: HTMLDialogElement) { this.open = false } })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.useRealTimers() })
function fetcher(overrides?: (url: string, options?: RequestInit) => Response | Promise<Response> | undefined) {
  const fn = vi.fn((input: RequestInfo | URL, options?: RequestInit) => {
    const url = String(input)
    const override = overrides?.(url, options)
    if (override) return Promise.resolve(override)
    if (url.endsWith('/start-readiness')) return Promise.resolve(json(ready))
    if (url.endsWith('/recommendations')) return Promise.resolve(json(intelligentRecommendationData('Accepted')))
    if (url.endsWith('/start-receipt')) return Promise.resolve(json(receipt))
    if (url.endsWith('/start')) return Promise.resolve(json(receipt, 202))
    return Promise.resolve(json({}, 404))
  })
  vi.stubGlobal('fetch', fn); return fn
}

it('uses the Figma title and exactly Cancel / Start Test footer labels with server-owned configuration', async () => {
  fetcher(); render(<Wrapper />)
  const dialog = screen.getByRole('dialog', { name: 'Start Test' })
  expect(await within(dialog).findByText('Ready to Start')).toBeVisible()
  expect(within(dialog).getByText(ready.endpoint)).toBeVisible()
  expect(within(dialog).getByText(ready.configured_profile)).toBeVisible()
  expect(within(dialog).getByText(recommendation.target)).toBeVisible()
  expect(within(dialog).getByRole('button', { name: 'Start Test' })).toBeEnabled()
  expect(within(dialog).queryByRole('button', { name: 'Confirm Start Test' })).not.toBeInTheDocument()
  fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
  expect(closed).toHaveBeenCalledOnce(); expect(started).not.toHaveBeenCalled()
})

it('does not fabricate configured profiles or Ready state for unavailable execution', async () => {
  const fn = fetcher(url => url.endsWith('/start-readiness') ? json({ ...ready, ready: false, reason_code: 'nikto_tool_unavailable',
    snapshot_digest: null, configured_profile: null, endpoint: null }) : undefined)
  render(<Wrapper />)
  expect(await screen.findByText('Unavailable — nikto_tool_unavailable')).toBeVisible()
  expect(screen.getByText('Not configured')).toBeVisible()
  expect(screen.getByRole('button', { name: 'Start Test' })).toBeDisabled()
  fireEvent.click(screen.getByRole('button', { name: 'Start Test' }))
  expect(fn.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false)
})

it('sends the captured digest with CSRF and prevents immediate double-click submissions', async () => {
  let resolve!: (response: Response) => void
  const fn = fetcher((url, options) => url.endsWith('/start') && options?.method === 'POST'
    ? new Promise<Response>(r => { resolve = r }) : undefined)
  render(<Wrapper />)
  await screen.findByText('Ready to Start')
  const button = screen.getByRole('button', { name: 'Start Test' })
  fireEvent.click(button); fireEvent.click(button)
  const posts = fn.mock.calls.filter(([, options]) => options?.method === 'POST')
  expect(posts).toHaveLength(1)
  expect(JSON.parse(posts[0][1]!.body as string)).toEqual({ snapshot_digest: ready.snapshot_digest })
  expect(posts[0][1]!.headers).toMatchObject({ 'X-CSRF-Token': 'test-csrf' })
  expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled()
  await act(async () => { resolve(json(receipt, 202)) })
  expect(started).toHaveBeenCalledOnce(); expect(closed).toHaveBeenCalledOnce()
})

it('recovers a lost response only through authoritative GET and never repeats POST', async () => {
  const fn = fetcher((url, options) => url.endsWith('/start') && options?.method === 'POST'
    ? Promise.reject(new Error('lost')) : undefined)
  render(<Wrapper />); await screen.findByText('Ready to Start')
  fireEvent.click(screen.getByRole('button', { name: 'Start Test' }))
  await waitFor(() => expect(started).toHaveBeenCalledOnce())
  expect(fn.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1)
  expect(fn.mock.calls.some(([url]) => String(url).endsWith('/start-receipt'))).toBe(true)
})

it('keeps uncertainty after missing readback and only offers read-only status verification', async () => {
  let available = false
  const fn = fetcher((url, options) => url.endsWith('/start') && options?.method === 'POST' ? Promise.reject(new Error('lost'))
    : url.endsWith('/start-receipt') ? json(available ? receipt : {}, available ? 200 : 404) : undefined)
  render(<Wrapper />); await screen.findByText('Ready to Start')
  fireEvent.click(screen.getByRole('button', { name: 'Start Test' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('unverified')
  expect(screen.getByRole('button', { name: 'Start Test' })).toBeDisabled()
  available = true; fireEvent.click(screen.getByRole('button', { name: 'Check scheduling status' }))
  await waitFor(() => expect(started).toHaveBeenCalledOnce())
  expect(fn.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1)
})

it('treats 409 as stale review and never automatically retries the Start action', async () => {
  const fn = fetcher((url, options) => url.endsWith('/start') && options?.method === 'POST' ? json({},409) : undefined)
  render(<Wrapper />); await screen.findByText('Ready to Start')
  fireEvent.click(screen.getByRole('button', { name: 'Start Test' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('reviewed state changed')
  expect(screen.getByRole('button', { name: 'Start Test' })).toBeDisabled()
  expect(fn.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1)
})

it('aborts an in-flight POST on unmount and ignores late callbacks', async () => {
  let resolve!: (response: Response) => void
  const fn = fetcher((url, options) => url.endsWith('/start') && options?.method === 'POST'
    ? new Promise<Response>(r => { resolve = r }) : undefined)
  const view = render(<Wrapper />); await screen.findByText('Ready to Start')
  fireEvent.click(screen.getByRole('button', { name: 'Start Test' }))
  const post = fn.mock.calls.find(([, options]) => options?.method === 'POST')!
  view.unmount(); expect(post[1]!.signal!.aborted).toBe(true)
  await act(async () => { resolve(json(receipt,202)) })
  expect(started).not.toHaveBeenCalled()
})

it('validates activated Nikto planning state without granting execution or enabling ZAP', async () => {
  const { getRecommendations } = await import('../services/testing')
  const data = intelligentRecommendationData('Accepted')
  Object.assign(data.recommendations[0], { execution_status: 'requires_start_review',
    tool_integration_status: 'integrated', execution_unavailability_reason: 'explicit_start_required' })
  vi.stubGlobal('fetch', vi.fn(async () => json(data)))
  const result = await getRecommendations(assessmentId, new AbortController().signal)
  expect(result.recommendations[0].execution_available).toBe(false)
  expect(result.recommendations[0].review_outcome).toBe('Accepted')
  data.recommendations[0].suggested_tool = 'OWASP ZAP'
  await expect(getRecommendations(assessmentId, new AbortController().signal)).rejects.toThrow()
})
