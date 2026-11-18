import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import TestingPage from './TestingPage'
import type { ExecutionStatus } from '../services/testing'
import { assessmentId, executionDetails, recommendationData, testingData } from '../test-fixtures/testing'

const reply = (value: unknown, status = 200) => ({ ok: status < 400, status, json: async () => value })
const expired = vi.fn()
const showModal = Object.getOwnPropertyDescriptor(HTMLDialogElement.prototype, 'showModal')
const closeDialog = Object.getOwnPropertyDescriptor(HTMLDialogElement.prototype, 'close')
beforeEach(() => {
  expired.mockReset()
  Object.defineProperty(HTMLDialogElement.prototype, 'close', { configurable: true, value(this: HTMLDialogElement) { this.open = false } })
  Object.defineProperty(HTMLDialogElement.prototype, 'showModal', { configurable: true, value(this: HTMLDialogElement) { this.open = true } })
})
afterEach(() => {
  cleanup(); vi.useRealTimers(); vi.unstubAllGlobals()
  if (closeDialog) Object.defineProperty(HTMLDialogElement.prototype, 'close', closeDialog)
  else Reflect.deleteProperty(HTMLDialogElement.prototype, 'close')
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
  const technical = within(dialog).getByText('Technical Details').closest('details')!
  expect(technical.open).toBe(false)
  fireEvent.click(within(dialog).getByText('Technical Details'))
  expect(await within(dialog).findByText(/No execution attempt recorded/)).toBeVisible()
  const output = within(dialog).getByText('Original Tool Output').closest('details')!
  expect(output.open).toBe(false)
  fireEvent.click(within(dialog).getByText('Original Tool Output'))
  expect(await within(dialog).findByText('No scanner evidence recorded.')).toBeVisible()
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
    const fetcher = vi.fn<(input: RequestInfo | URL, options?: RequestInit) => Promise<ReturnType<typeof reply>>>(async (input) => reply(
      String(input).endsWith('/synthetic-execution-0') ? details : testingData([status])))
    vi.stubGlobal('fetch', fetcher)
    page()
    fireEvent.click(await screen.findByRole('button', { name: /View Details:/ }))
    const dialog = await screen.findByRole('dialog')
    expect(await within(dialog).findByRole('heading', { name: 'Test Details' })).toBeVisible()
    expect(await within(dialog).findByRole('region', { name: 'Selected Test' })).toHaveTextContent(status)
    expect(within(dialog).getByText('Technical Details')).toBeVisible()
    expect(within(dialog).getByRole('region', { name: 'Test Results' })).toBeVisible()
    if (status === 'Failed') {
      fireEvent.click(within(dialog).getByText('Technical Details'))
      expect(within(dialog).getByText('scanner error')).toBeVisible()
    }
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
  const fetcher = vi.fn<(input: RequestInfo | URL, options?: RequestInit) => Promise<ReturnType<typeof reply>>>(async (input) => reply(
    String(input).endsWith('/recommendations')
      ? { assessment_id: assessmentId, count: 0, recommendations: [], execution_authorized: false }
      : testingData(['Completed'])))
  vi.stubGlobal('fetch', fetcher)
  page()
  const activity = await screen.findByRole('table', { name: 'Test Activity' })
  expect(activity).toBeVisible()
  fireEvent.click(screen.getByRole('tab', { name: /Recommendations/ }))
  expect(screen.getByRole('tab', { name: /Recommendations/ })).toHaveAttribute('aria-selected', 'true')
  expect(screen.getByRole('tabpanel', { name: /Recommendations/ })).toBeVisible()
  expect(await screen.findByText('No suggested next steps yet')).toBeVisible()
  expect(screen.getByLabelText('0 recommendations')).toBeVisible()
  expect(screen.queryByRole('table', { name: 'Test Activity' })).not.toBeInTheDocument()
  expect(screen.getByRole('tab', { name: 'Testing Completion' })).toBeDisabled()
  expect(screen.getByRole('button', { name: 'Run Manual Test' })).toBeDisabled()
  fireEvent.click(screen.getByRole('tab', { name: 'Test Activity' }))
  expect(screen.getByRole('table', { name: 'Test Activity' })).toBeVisible()
  expect(fetcher.mock.calls.every(([, options]) => !(options as RequestInit | undefined)?.method)).toBe(true)
})

it('renders only API-provided T-04B recommendations and provenance without starting tests', async () => {
  const item = {
    id: 'stable-recommendation', kind: 'review_host_discovery', title: 'Review responding host',
    target_id: 'target-1', target: '192.0.2.10', service: null, port: null,
    reason: 'A completed discovery observation recorded this host as responding.',
    source_observation_id: 'observation-1', source_evidence_id: 'evidence-1',
    execution_available: false, execution_status: 'not_supported', suggested_test: null, suggested_tool: null,
  }
  const fetcher = vi.fn<(input: RequestInfo | URL, options?: RequestInit) => Promise<ReturnType<typeof reply>>>(async (input) => reply(
    String(input).endsWith('/recommendations')
      ? { assessment_id: assessmentId, count: 1, recommendations: [item], execution_authorized: false }
      : testingData(['Completed'])))
  vi.stubGlobal('fetch', fetcher)
  page()
  await screen.findByRole('table', { name: 'Test Activity' })
  fireEvent.click(screen.getByRole('tab', { name: /Recommendations/ }))
  expect(await screen.findByText('Review responding host')).toBeVisible()
  expect(screen.getByLabelText('1 recommendations')).toBeVisible()
  expect(screen.getByText('192.0.2.10')).toBeVisible()
  const trigger = screen.getByRole('button', { name: 'Review Suggestion' })
  fireEvent.click(trigger)
  const drawer = screen.getByRole('dialog', { name: 'Review Recommendation' })
  expect(within(drawer).queryByText('observation-1')).not.toBeInTheDocument()
  expect(within(drawer).queryByText('evidence-1')).not.toBeInTheDocument()
  for (const heading of ['Suggestion Information', 'Why Is This Suggested?', 'Source Test', 'Proposed Test']) {
    expect(within(drawer).getByRole('heading', { name: heading })).toBeVisible()
  }
  expect(within(drawer).getByRole('button', { name: 'Start Test' })).toBeDisabled()
  fireEvent.click(within(drawer).getByRole('button', { name: 'Choose Alternative' }))
  expect(within(drawer).getByRole('heading', { name: 'Choose Alternative' })).toBeVisible()
  expect(within(drawer).getByLabelText('Security Tool')).toBeDisabled()
  expect(within(drawer).getByLabelText('Test Profile')).toBeDisabled()
  expect(within(drawer).getByRole('button', { name: 'Confirm Alternative' })).toBeDisabled()
  for (const heading of ['Current Recommendation', 'Select Alternative', 'Selected Test', 'Compatibility Status']) {
    expect(within(drawer).getByRole('heading', { name: heading })).toBeVisible()
  }
  expect(await within(drawer).findByText('Unable to verify alternatives. No test can be confirmed.')).toBeVisible()
  fireEvent.click(within(drawer).getByRole('button', { name: 'Cancel' }))
  expect(within(drawer).getByRole('heading', { name: 'Review Recommendation' })).toBeVisible()
  fireEvent.click(within(drawer).getByRole('button', { name: 'Close recommendation review' }))
  expect(screen.queryByRole('dialog', { name: 'Review Recommendation' })).not.toBeInTheDocument()
  expect(trigger).toHaveFocus()
  expect(fetcher.mock.calls.every(([, options]) => !(options as RequestInit | undefined)?.method)).toBe(true)
})

it('does not display a fabricated empty state when recommendations fail', async () => {
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => String(input).endsWith('/recommendations')
    ? reply({}, 503) : reply(testingData(['Completed']))))
  page()
  await screen.findByRole('table')
  fireEvent.click(screen.getByRole('tab', { name: /Recommendations/ }))
  expect(await screen.findByText(/Unable to load recommendations/)).toBeVisible()
  expect(screen.queryByText('No suggested next steps yet')).not.toBeInTheDocument()
})


it('clears previous assessment content immediately when the assessment changes', async () => {
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    if (String(input).includes('different-assessment')) return new Promise<ReturnType<typeof reply>>(() => {})
    return reply(testingData(['Completed']))
  }))
  const view = page()
  await screen.findByRole('table', { name: 'Test Activity' })
  view.rerender(<TestingPage assessmentId="different-assessment" onExpired={expired} />)
  expect(screen.getByRole('status')).toHaveTextContent('Loading Testing')
  expect(screen.queryByRole('table')).not.toBeInTheDocument()
  expect(screen.queryByText('192.0.2.1')).not.toBeInTheDocument()
})

it('shows verified source metadata and fail-closed alternative checks without exposing identifiers', async () => {
  const recs = recommendationData()
  const check = { assessment_id: assessmentId, recommendation_id: recs.recommendations[0].id,
    eligible: false, execution_available: false, authorization_available: false,
    available_profiles: [], reason_code: 'followup_profile_not_supported' }
  const fetcher = vi.fn<(input: RequestInfo | URL, options?: RequestInit) => Promise<ReturnType<typeof reply>>>(async input => {
    const url = String(input)
    return reply(url.endsWith('/recommendations') ? recs
      : url.endsWith('/eligibility') || url.endsWith('/authorization-review') ? check : testingData(['Completed']))
  })
  vi.stubGlobal('fetch', fetcher)
  page()
  await screen.findByRole('table')
  fireEvent.click(screen.getByRole('tab', { name: /Recommendations/ }))
  fireEvent.click(await screen.findByRole('button', { name: 'Review Suggestion' }))
  const drawer = screen.getByRole('dialog')
  const source = within(drawer).getByRole('region', { name: 'Source Test' })
  expect(source).toHaveTextContent('Network Discovery')
  expect(source).toHaveTextContent('Nmap')
  expect(source).toHaveTextContent('Completed')
  expect(within(drawer).getAllByText('Not identified')).toHaveLength(2)
  expect(screen.queryByText('synthetic-observation')).not.toBeInTheDocument()
  expect(screen.queryByText('synthetic-evidence')).not.toBeInTheDocument()
  expect(within(drawer).getByRole('button', { name: 'Start Test' })).toBeDisabled()
  fireEvent.click(within(drawer).getByRole('button', { name: 'Choose Alternative' }))
  expect(await within(drawer).findByText('No supported follow-up test profile is available for this recommendation.')).toBeVisible()
  expect(within(drawer).getByRole('button', { name: 'Confirm Alternative' })).toBeDisabled()
  expect(within(drawer).getByLabelText('Security Tool')).toHaveLength(1)
  expect(within(drawer).getByLabelText('Test Profile')).toHaveLength(1)
  expect(fetcher.mock.calls.some(([url]) => String(url).endsWith('/eligibility'))).toBe(true)
  expect(fetcher.mock.calls.some(([url]) => String(url).endsWith('/authorization-review'))).toBe(true)
  expect(fetcher.mock.calls.every(([, options]) => !options?.method)).toBe(true)
})

it.each([false, true])('loads original output only on disclosure and handles unavailable=%s', async unavailable => {
  const details = executionDetails()
  details.status = 'Completed'
  details.observations = [{ id: 'synthetic-observation', type: 'host_discovery',
    data: { address: '192.0.2.1', status: 'up' }, partial: false, evidence_id: 'synthetic-evidence' }]
  details.evidence = [{ id: 'synthetic-evidence', format: 'nmap-xml', size_bytes: 25,
    partial: false, collected_at: '2026-11-16T10:00:00Z', sha256: 'a'.repeat(64) }]
  const raw = '<script>inert text</script>'
  const fetcher = vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    if (url.endsWith('/output')) return reply(unavailable ? {} : {
      assessment_id: assessmentId, execution_id: details.id, evidence_id: 'synthetic-evidence',
      content: raw, format: 'nmap-xml', partial: false,
    }, unavailable ? 409 : 200)
    return reply(url.endsWith('/synthetic-execution-0') ? details : testingData(['Completed']))
  })
  vi.stubGlobal('fetch', fetcher)
  page()
  fireEvent.click(await screen.findByRole('button', { name: /View Details:/ }))
  const drawer = screen.getByRole('dialog')
  expect(await within(drawer).findByRole('table')).toHaveTextContent('192.0.2.1')
  expect(within(drawer).getByRole('table')).toHaveTextContent('Responding')
  expect(within(drawer).queryByText('HTTP')).not.toBeInTheDocument()
  const output = within(drawer).getByText('Original Tool Output')
  expect(output.closest('details')!.open).toBe(false)
  expect(within(drawer).getByText('Technical Details').closest('details')!.open).toBe(false)
  expect(fetcher.mock.calls.some(([url]) => String(url).endsWith('/output'))).toBe(false)
  fireEvent.click(output)
  if (unavailable) expect(await within(drawer).findByRole('alert')).toHaveTextContent('Original tool output is unavailable.')
  else {
    expect(await within(drawer).findByText(raw)).toBeVisible()
    expect(drawer.querySelector('script')).toBeNull()
  }
  fireEvent.click(output)
  expect(output.closest('details')!.open).toBe(false)
})

it('rejects malformed alternative authorization responses instead of enabling confirmation', async () => {
  const recs = recommendationData()
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    return reply(url.endsWith('/recommendations') ? recs
      : url.includes('/recommendations/') ? { assessment_id: assessmentId, eligible: true, execution_available: true }
      : testingData(['Completed']))
  }))
  page()
  await screen.findByRole('table')
  fireEvent.click(screen.getByRole('tab', { name: /Recommendations/ }))
  fireEvent.click(await screen.findByRole('button', { name: 'Review Suggestion' }))
  fireEvent.click(screen.getByRole('button', { name: 'Choose Alternative' }))
  expect(await screen.findByText('Unable to verify alternatives. No test can be confirmed.')).toBeVisible()
  expect(screen.getByRole('button', { name: 'Confirm Alternative' })).toBeDisabled()
})

it.each([401, 403, 404])('does not convert recommendation access failure %s into an empty list', async status => {
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) =>
    String(input).endsWith('/recommendations') ? reply({}, status) : reply(testingData(['Completed']))))
  page()
  await screen.findByRole('table')
  fireEvent.click(screen.getByRole('tab', { name: /Recommendations/ }))
  expect(await screen.findByRole('alert')).toHaveTextContent(status === 401 ? 'session has ended' : 'Recommendations unavailable')
  expect(screen.queryByText('No suggested next steps yet')).not.toBeInTheDocument()
  expect(expired).toHaveBeenCalledTimes(status === 401 ? 1 : 0)
})
