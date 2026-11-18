import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import TestingPage from './TestingPage'
import type { ExecutionStatus } from '../services/testing'
import { assessmentId, executionDetails, testingData } from '../test-fixtures/testing'

const reply = (value: unknown, status = 200) => ({ ok: status < 400, status, json: async () => value })
const expired = vi.fn()
const showModal = Object.getOwnPropertyDescriptor(HTMLDialogElement.prototype, 'showModal')
beforeEach(() => {
  expired.mockReset()
  Object.defineProperty(HTMLDialogElement.prototype, 'showModal', { configurable: true, value(this: HTMLDialogElement) { this.open = true } })
})
afterEach(() => {
  cleanup(); vi.useRealTimers(); vi.unstubAllGlobals()
  if (showModal) Object.defineProperty(HTMLDialogElement.prototype, 'showModal', showModal)
  else Reflect.deleteProperty(HTMLDialogElement.prototype, 'showModal')
})
function page() { return render(<TestingPage assessmentId={assessmentId} onExpired={expired} />) }

it('distinguishes loading from the empty T-00 state', async () => {
  let resolve!: (result: ReturnType<typeof reply>) => void
  vi.stubGlobal('fetch', vi.fn(() => new Promise(done => { resolve = done })))
  page()
  expect(screen.getByRole('status')).toHaveTextContent('Loading Testing')
  expect(screen.queryByText('No tests have been run yet')).not.toBeInTheDocument()
  await act(async () => resolve(reply(testingData())))
  expect(await screen.findByText('No tests have been run yet')).toBeVisible()
  for (const label of ['Total Tests', 'In Progress', 'Completed', 'Failed']) {
    expect(within(screen.getByRole('region', { name: label })).getByText('0')).toBeVisible()
  }
  expect(screen.queryByRole('table')).not.toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Run Manual Test' })).toBeDisabled()
  expect(screen.getByRole('tab', { name: /Recommendations/ })).toBeEnabled()
  expect(screen.getByRole('tab', { name: 'Testing Completion' })).toBeDisabled()
})

it.each(['Queued', 'Running', 'Completed', 'Failed', 'Stopped', 'Blocked', 'Cancelled'] as ExecutionStatus[])(
  'renders persisted %s without inventing results', async status => {
    vi.stubGlobal('fetch', vi.fn(async () => reply(testingData([status]))))
    page()
    const table = await screen.findByRole('table', { name: 'Test Activity' })
    expect(within(table).getByText(status)).toBeVisible()
    expect(within(table).getByText('192.0.2.1')).toBeVisible()
    expect(within(screen.getByRole('region', { name: 'Total Tests' })).getByText('1')).toBeVisible()
    expect(within(screen.getByRole('region', { name: 'In Progress' })).getByText(status === 'Running' ? '1' : '0')).toBeVisible()
    expect(screen.queryByText('No tests have been run yet')).not.toBeInTheDocument()
    if (status === 'Queued') expect(screen.getByText(/queued tests are not running/)).toBeVisible()
    expect(screen.getByText('No discovery observations recorded.')).toBeVisible()
    expect(screen.queryByText(/identified SSH/)).not.toBeInTheDocument()
  })

it('renders mixed status counts from the overview contract', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => reply(testingData(['Queued', 'Running', 'Completed', 'Failed', 'Blocked']))))
  page()
  await screen.findByRole('table')
  expect(within(screen.getByRole('region', { name: 'Total Tests' })).getByText('5')).toBeVisible()
  for (const label of ['In Progress', 'Completed', 'Failed']) expect(within(screen.getByRole('region', { name: label })).getByText('1')).toBeVisible()
  expect(screen.getAllByRole('row')).toHaveLength(6)
})

it('treats a network failure as an error, not an empty assessment, and retries', async () => {
  const fetcher = vi.fn().mockRejectedValueOnce(new Error('offline')).mockResolvedValue(reply(testingData(['Queued'])))
  vi.stubGlobal('fetch', fetcher)
  page()
  expect(await screen.findByRole('alert')).toHaveTextContent('Unable to refresh Testing')
  expect(screen.queryByText('No tests have been run yet')).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
  expect(await screen.findByRole('table')).toBeVisible()
  expect(fetcher).toHaveBeenCalledWith('/api/v1/assessments/' + assessmentId + '/testing', expect.objectContaining({ credentials: 'same-origin', cache: 'no-store' }))
})

it.each([401, 403, 404])('handles protected API failure %s without showing assessment data', async status => {
  vi.stubGlobal('fetch', vi.fn(async () => reply({}, status)))
  page()
  expect(await screen.findByRole('alert')).toHaveTextContent(status === 401 ? 'session has ended' : 'Assessment unavailable')
  expect(expired).toHaveBeenCalledTimes(status === 401 ? 1 : 0)
  expect(screen.queryByRole('table')).not.toBeInTheDocument()
})

it('loads functional read-only details without issuing an execution write', async () => {
  const fetcher = vi.fn<(input: RequestInfo | URL, options?: RequestInit) => Promise<ReturnType<typeof reply>>>(async (input) => reply(String(input).endsWith('/synthetic-execution-0') ? executionDetails() : testingData(['Queued'])))
  vi.stubGlobal('fetch', fetcher)
  page()
  const button = await screen.findByRole('button', { name: /View Details:/ })
  fireEvent.click(button)
  const dialog = await screen.findByRole('dialog')
  expect(await within(dialog).findByText(/No execution attempt recorded/)).toBeVisible()
  expect(within(dialog).getByText('No scanner evidence recorded.')).toBeVisible()
  fireEvent.click(within(dialog).getByRole('button', { name: 'Close' }))
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  expect(button).toHaveFocus()
  expect(fetcher.mock.calls.every(([, options]) => !(options as RequestInit | undefined)?.method)).toBe(true)
})

it('rejects inconsistent counters rather than displaying misleading totals', async () => {
  const invalid = testingData(['Queued']); invalid.counts.in_progress = 1
  vi.stubGlobal('fetch', vi.fn(async () => reply(invalid)))
  page()
  expect(await screen.findByRole('alert')).toBeVisible()
  expect(screen.queryByRole('table')).not.toBeInTheDocument()
})

it('refreshes execution statuses without overlapping requests and cancels on unmount', async () => {
  vi.useFakeTimers()
  let resolve!: (value: ReturnType<typeof reply>) => void
  const fetcher = vi.fn().mockResolvedValueOnce(reply(testingData(['Queued'])))
    .mockImplementationOnce(() => new Promise(done => { resolve = done }))
  vi.stubGlobal('fetch', fetcher)
  const view = page()
  await act(async () => { await Promise.resolve(); await Promise.resolve() })
  await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
  expect(fetcher).toHaveBeenCalledTimes(2)
  await act(async () => { await vi.advanceTimersByTimeAsync(10000) })
  expect(fetcher).toHaveBeenCalledTimes(2)
  await act(async () => resolve(reply(testingData(['Running']))))
  expect(within(screen.getByRole('table')).getByText('Running')).toBeVisible()
  view.unmount()
  const signal = fetcher.mock.calls[1][1].signal as AbortSignal
  expect(signal.aborted).toBe(true)
  await act(async () => { await vi.advanceTimersByTimeAsync(10000) })
  expect(fetcher).toHaveBeenCalledTimes(2)
})

it.each(['Running', 'Completed', 'Failed'] as ExecutionStatus[])(
  'shows state-specific %s execution details without writing to the API', async status => {
    const details = { ...executionDetails(), status,
      attempts: [{ id: 'attempt-1', attempt_number: 1, status: status === 'Completed' ? 'Succeeded' : status,
        reason_code: status === 'Failed' ? 'scanner_error' : null, started_at: '2026-11-16T10:01:00Z',
        finished_at: status === 'Running' ? null : '2026-11-16T10:02:00Z',
        exit_code: status === 'Failed' ? 1 : status === 'Completed' ? 0 : null, recovery_reason: null }] }
    const fetcher = vi.fn(async (input: RequestInfo | URL, _options?: RequestInit) => reply(
      String(input).endsWith('/synthetic-execution-0') ? details : testingData([status])))
    vi.stubGlobal('fetch', fetcher)
    page()
    fireEvent.click(await screen.findByRole('button', { name: /View Details:/ }))
    const dialog = await screen.findByRole('dialog')
    expect(await within(dialog).findByRole('heading', { name: status === 'Running'
      ? 'Running Test Details' : status === 'Completed' ? 'Completed Test Details' : 'Failed Test Details' })).toBeVisible()
    expect(within(dialog).getByText('Technical Details')).toBeVisible()
    expect(within(dialog).getByRole('region', { name: 'Test results' })).toBeVisible()
    if (status === 'Failed') expect(within(dialog).getByText('scanner_error')).toBeVisible()
    expect(fetcher.mock.calls.every(([, options]) => !(options as RequestInit | undefined)?.method)).toBe(true)
  })

it('shows actual execution events with friendly labels and timestamps', async () => {
  const overview = testingData(['Completed'])
  overview.recent_activity = [{ event: 'execution_finished', execution_id: 'synthetic-execution-0',
    occurred_at: '2026-11-16T10:02:00Z' }]
  vi.stubGlobal('fetch', vi.fn(async () => reply(overview)))
  page()
  expect(await screen.findByText('Network Discovery: Execution finished')).toBeVisible()
})

it('switches to T-04A Recommendations and back without writing or inventing suggestions', async () => {
  const fetcher = vi.fn(async (_input: RequestInfo | URL, _options?: RequestInit) => reply(testingData(['Completed'])))
  vi.stubGlobal('fetch', fetcher)
  page()
  const activity = await screen.findByRole('table', { name: 'Test Activity' })
  expect(activity).toBeVisible()
  fireEvent.click(screen.getByRole('tab', { name: /Recommendations/ }))
  expect(screen.getByRole('tab', { name: /Recommendations/ })).toHaveAttribute('aria-selected', 'true')
  expect(screen.getByRole('tabpanel', { name: /Recommendations/ })).toBeVisible()
  expect(screen.getByText('No suggested next steps yet')).toBeVisible()
  expect(screen.getByLabelText('0 recommendations')).toBeVisible()
  expect(screen.queryByRole('table', { name: 'Test Activity' })).not.toBeInTheDocument()
  expect(screen.getByRole('tab', { name: 'Testing Completion' })).toBeDisabled()
  expect(screen.getByRole('button', { name: 'Run Manual Test' })).toBeDisabled()
  fireEvent.click(screen.getByRole('tab', { name: 'Test Activity' }))
  expect(screen.getByRole('table', { name: 'Test Activity' })).toBeVisible()
  expect(fetcher.mock.calls.every(([, options]) => !(options as RequestInit | undefined)?.method)).toBe(true)
})
