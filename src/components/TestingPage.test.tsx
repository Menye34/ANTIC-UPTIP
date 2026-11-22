import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import TestingPage from './TestingPage'
import type { ExecutionStatus } from '../services/testing'
import { assessmentId, executionDetails, testingData, recommendationData, completionReview, completedCompletionReview, intelligentRecommendationData } from '../test-fixtures/testing'

const reply = (value: unknown, status = 200) => ({ ok: status < 400, status, json: async () => value })
const expired = vi.fn()
const closeDialog = Object.getOwnPropertyDescriptor(HTMLDialogElement.prototype, 'close')
const showModal = Object.getOwnPropertyDescriptor(HTMLDialogElement.prototype, 'showModal')
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
  expect(screen.getByRole('tab', { name: 'Testing Completion' })).toBeEnabled()
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
  fireEvent.click(await within(dialog).findByText('Technical Details'))
  expect(await within(dialog).findByText(/No execution attempt recorded/)).toBeVisible()
  fireEvent.click(within(dialog).getByText('Original Tool Output'))
  expect(within(dialog).getByText('No original tool output recorded.')).toBeVisible()
  fireEvent.click(within(dialog).getByRole('button', { name: 'Close test details' }))
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
    const fetcher = vi.fn<(input: RequestInfo | URL, options?: RequestInit) => Promise<ReturnType<typeof reply>>>(async input => reply(
      String(input).endsWith('/synthetic-execution-0') ? details : testingData([status])))
    vi.stubGlobal('fetch', fetcher)
    page()
    fireEvent.click(await screen.findByRole('button', { name: /View Details:/ }))
    const dialog = await screen.findByRole('dialog')
    expect(await within(dialog).findByRole('heading', { name: status === 'Running'
      ? 'Running Test Details' : status === 'Completed' ? 'Test Details' : 'Failed Test Details' })).toBeVisible()
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
  const fetcher = vi.fn<(input: RequestInfo | URL, options?: RequestInit) => Promise<ReturnType<typeof reply>>>(async (input) => reply(
    String(input).endsWith('/recommendations')
      ? { assessment_id: assessmentId, count: 0, recommendations: [], execution_authorized: false,
          decision_counts: { total: 0, pending_review: 0, reviewed: 0, deferred: 0, pending_completion: 0 } }
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
  expect(screen.getByRole('tab', { name: 'Testing Completion' })).toBeEnabled()
  expect(screen.getByRole('button', { name: 'Run Manual Test' })).toBeDisabled()
  fireEvent.click(screen.getByRole('tab', { name: 'Test Activity' }))
  expect(screen.getByRole('table', { name: 'Test Activity' })).toBeVisible()
  expect(fetcher.mock.calls.every(([, options]) => !(options as RequestInit | undefined)?.method)).toBe(true)
})

it('renders only API-provided T-04B recommendations and provenance without starting tests', async () => {
  const item = {
    decision: null, id: 'stable-recommendation', kind: 'review_host_discovery', title: 'Review responding host',
    target_id: 'target-1', target: '192.0.2.10', service: null, port: null,
    reason: 'A completed discovery observation recorded this host as responding.',
    source_observation_id: 'observation-1', source_evidence_id: 'evidence-1',
    execution_available: false, execution_status: 'not_supported', suggested_test: null, suggested_tool: null,
  }
  const fetcher = vi.fn<(input: RequestInfo | URL, options?: RequestInit) => Promise<ReturnType<typeof reply>>>(async (input) => reply(
    String(input).endsWith('/recommendations')
      ? { assessment_id: assessmentId, count: 1, recommendations: [item], execution_authorized: false,
          decision_counts: { total: 1, pending_review: 1, reviewed: 0, deferred: 0, pending_completion: 1 } }
      : testingData(['Completed'])))
  vi.stubGlobal('fetch', fetcher)
  page()
  await screen.findByRole('table', { name: 'Test Activity' })
  fireEvent.click(screen.getByRole('tab', { name: /Recommendations/ }))
  expect(await screen.findByText('Review responding host')).toBeVisible()
  expect(screen.getByLabelText('1 recommendations')).toBeVisible()
  expect(screen.getByText('192.0.2.10')).toBeVisible()
  const trigger = screen.getByRole('button', { name: 'Review Recommendation' })
  fireEvent.click(trigger)
  const drawer = screen.getByRole('dialog', { name: 'Review Recommendation' })
  expect(within(drawer).queryByText('observation-1')).not.toBeInTheDocument()
  expect(within(drawer).queryByText('evidence-1')).not.toBeInTheDocument()
  for (const heading of ['Recommendation Information', 'Why is this recommended?', 'Source Test', 'Proposed Test']) {
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
  fireEvent.click(await screen.findByRole('button', { name: 'Review Recommendation' }))
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
  fireEvent.click(await screen.findByRole('button', { name: 'Review Recommendation' }))
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

it('opens Testing Completion inside the existing Testing tab and blocks incomplete tests', async () => {
  const snapshot = {
    assessment_id: assessmentId, assessment_name: 'Synthetic assessment', lifecycle_status: 'Testing', ready: false,
    can_complete: true, snapshot_schema_version: 2,
    blocker_details: [{ code: 'active_tests', message: 'Queued execution remains.', count: 1, action: 'view_tests' }],
    snapshot_digest: 'a'.repeat(64),
    summary: {
      total: 1, counts: { Queued: 1, Running: 0, Completed: 0, Failed: 0,
        Stopped: 0, Blocked: 0, Cancelled: 0 },
      active_attempts: 0, active_execution_requests: 1, recovery_required_requests: 0,
      decision_counts: { total: 0, pending_review: 0, reviewed: 0, deferred: 0, pending_completion: 0 },
      deferred_recommendations: 0, processing_errors: 0, processing_pending: 0,
      missing_processing: 0, recommendation_count: 0,
      pending_recommendation_ids: [], reviewed_recommendations: 0,
      candidate_findings: null, blockers: ['active_tests'],
    },
    recommendations: [], completion: null,
  }
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => reply(
    String(input).endsWith('/testing/completion') ? snapshot : testingData(['Queued']))))
  page()
  await screen.findByRole('table', { name: 'Test Activity' })
  fireEvent.click(screen.getByRole('tab', { name: 'Testing Completion' }))
  expect(await screen.findByRole('heading', { name: 'Testing Completion Review' })).toBeVisible()
  expect(screen.getByRole('button', { name: 'Complete Testing' })).toBeDisabled()
  fireEvent.click(screen.getByRole('button', { name: 'View Tests' }))
  expect(screen.getByRole('table', { name: 'Test Activity' })).toBeVisible()
})


it('shows ready confirmation and persisted completion without faking a Findings route', async () => {
  const counts = { Queued: 0, Running: 0, Completed: 1, Failed: 0, Stopped: 0, Blocked: 0, Cancelled: 0 }
  const summary = {
    total: 1, counts, active_attempts: 0, active_execution_requests: 0, recovery_required_requests: 0,
    deferred_recommendations: 0, decision_counts: { total: 0, pending_review: 0, reviewed: 0, deferred: 0, pending_completion: 0 },
    processing_errors: 0,
    processing_pending: 0, missing_processing: 0, recommendation_count: 0,
    pending_recommendation_ids: [], reviewed_recommendations: 0,
    candidate_findings: null, blockers: [],
  }
  let done = false
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, options?: RequestInit) => {
    const url = String(input)
    if (url.endsWith('/testing/completion')) {
      if (options?.method === 'POST') {
        done = true
      }
      return reply({
        assessment_id: assessmentId, assessment_name: 'Synthetic assessment', can_complete: !done, snapshot_schema_version: 2, blocker_details: [],
        lifecycle_status: done ? 'Finding Review' : 'Testing',
        ready: !done, snapshot_digest: 'b'.repeat(64), summary,
        recommendations: [], completion: done ? {
          completed_at: '2026-11-18T10:00:00Z', actor_id: 'synthetic-analyst', snapshot: summary,
          snapshot_schema_version: 1, snapshot_digest: null,
        } : null,
      })
    }
    return reply(testingData(['Completed']))
  }))
  render(<TestingPage assessmentId={assessmentId} onExpired={expired} csrfToken="synthetic-csrf" />)
  await screen.findByRole('table', { name: 'Test Activity' })
  fireEvent.click(screen.getByRole('tab', { name: 'Testing Completion' }))
  expect(await screen.findByRole('heading', { name: 'Ready to complete' })).toBeVisible()
  fireEvent.click(screen.getByRole('button', { name: 'Complete Testing' }))
  expect(await screen.findByRole('heading', { name: 'Complete testing?' })).toBeVisible()
  const dialog = screen.getByRole('dialog')
  fireEvent.click(within(dialog).getByRole('button', { name: 'Complete Testing' }))
  expect(await screen.findByRole('heading', { name: 'Testing Completed' })).toBeVisible()
  expect(screen.getByRole('button', { name: 'Continue to Findings' })).toBeDisabled()
})

it.each([null, 'Reviewed', 'Deferred'] as const)('renders persisted decision %s in cards and dialog without a write', async decision => {
  const fetcher = vi.fn<(input: RequestInfo | URL, options?: RequestInit) => Promise<ReturnType<typeof reply>>>(async input => reply(String(input).endsWith('/recommendations')
    ? recommendationData(decision) : testingData(['Completed'])))
  vi.stubGlobal('fetch', fetcher)
  const first = page()
  await screen.findByRole('table')
  fireEvent.click(screen.getByRole('tab', { name: /Recommendations/ }))
  expect(await screen.findByText(decision ?? 'Pending Review')).toBeVisible()
  expect(screen.getByLabelText('1 recommendations')).toBeVisible()
  fireEvent.click(screen.getByRole('button', { name: 'Review Recommendation' }))
  const dialog = screen.getByRole('dialog', { name: 'Review Recommendation' })
  expect(within(dialog).getByText(decision ?? 'Pending Review')).toBeVisible()
  expect(within(dialog).getByRole('button', { name: 'Start Test' })).toBeDisabled()
  fireEvent.click(within(dialog).getByRole('button', { name: 'Close recommendation review' }))
  expect(fetcher.mock.calls.every(call => call.length === 1 || !(call[1] as RequestInit)?.method)).toBe(true)
  first.unmount()
  page()
  await screen.findByRole('table')
  fireEvent.click(screen.getByRole('tab', { name: /Recommendations/ }))
  expect(await screen.findByText(decision ?? 'Pending Review')).toBeVisible()
})

it.each(['missing decision', 'invalid decision', 'missing counters', 'inconsistent counters'])('rejects %s instead of showing Pending Review', async defect => {
  const value = structuredClone(recommendationData()) as unknown as { recommendations: Array<Record<string, unknown>>; decision_counts?: Record<string, number> }
  if (defect === 'missing decision') delete value.recommendations[0].decision
  if (defect === 'invalid decision') value.recommendations[0].decision = 'Approved'
  if (defect === 'missing counters') delete value.decision_counts
  if (defect === 'inconsistent counters') value.decision_counts!.reviewed = 1
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => reply(String(input).endsWith('/recommendations')
    ? value : testingData(['Completed']))))
  page()
  await screen.findByRole('table')
  fireEvent.click(screen.getByRole('tab', { name: /Recommendations/ }))
  expect(await screen.findByRole('alert')).toHaveTextContent('Unable to load recommendations')
  expect(screen.queryByText('Pending Review')).not.toBeInTheDocument()
})

it('renders mixed states with a total recommendation badge', async () => {
  const value = recommendationData()
  value.recommendations = [null, 'Reviewed', 'Deferred'].map((decision, i) => ({
    ...recommendationData(decision as 'Reviewed' | 'Deferred' | null).recommendations[0], id: String(i).repeat(64),
  }))
  value.count = 3
  value.decision_counts = { total: 3, pending_review: 1, reviewed: 1, deferred: 1, pending_completion: 2 }
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => reply(String(input).endsWith('/recommendations')
    ? value : testingData(['Completed']))))
  page()
  await screen.findByRole('table')
  fireEvent.click(screen.getByRole('tab', { name: /Recommendations/ }))
  expect(await screen.findByText('Deferred')).toBeVisible()
  expect(screen.getByText('Reviewed')).toBeVisible()
  expect(screen.getByText('Pending Review')).toBeVisible()
  expect(screen.getByLabelText('3 recommendations')).toBeVisible()
})

function decisionReview(decision: 'Reviewed' | 'Deferred' | null) {
  const counts = { Queued: 0, Running: 0, Completed: 1, Failed: 0, Stopped: 0, Blocked: 0, Cancelled: 0 }
  const recs = recommendationData(decision)
  return { assessment_id: assessmentId, assessment_name: 'Synthetic assessment',
    blocker_details: decision === 'Reviewed' ? [] : [{ code: 'pending_recommendations', message: 'Decision required.', count: 1, action: 'review_recommendations' }],
    lifecycle_status: 'Testing', ready: decision === 'Reviewed',
    snapshot_digest: 'b'.repeat(64), can_complete: true, snapshot_schema_version: 2,
    summary: { total: 1, counts, active_attempts: 0, active_execution_requests: 0,
      recovery_required_requests: 0, processing_errors: 0, processing_pending: 0, missing_processing: 0,
      recommendation_count: 1, pending_recommendation_ids: decision === 'Reviewed' ? [] : [recs.recommendations[0].id],
      reviewed_recommendations: recs.decision_counts.reviewed, deferred_recommendations: recs.decision_counts.deferred,
      decision_counts: recs.decision_counts, candidate_findings: null,
      blockers: decision === 'Reviewed' ? [] : ['pending_recommendations'] },
    recommendations: recs.recommendations.map(item => ({ id: item.id, title: item.title, decision })), completion: null }
}

it.each([
  ['success', 'Reviewed'], ['uncertain', 'Reviewed'], ['failed', 'Reviewed'],
  ['success', 'Deferred'], ['uncertain', 'Deferred'], ['failed', 'Deferred'],
] as const)('refreshes authoritative decisions after a %s %s write', async (outcome, requested) => {
  let saved: 'Reviewed' | 'Deferred' | null = null
  let finish: () => void = () => { throw new Error('Write not started') }
  const fetcher = vi.fn(async (input: RequestInfo | URL, options?: RequestInit) => {
    const url = String(input)
    if (url.endsWith('/completion/decisions')) {
      expect(options?.method).toBe('POST')
      await new Promise<void>(resolve => { finish = resolve })
      if (outcome !== 'failed') saved = requested
      if (outcome === 'uncertain') throw new Error('Response lost after commit')
      return reply({ assessment_id: assessmentId, recommendation_id: 'a'.repeat(64), decision: requested }, outcome === 'failed' ? 503 : 200)
    }
    if (url.endsWith('/recommendations')) return reply(recommendationData(saved))
    if (url.endsWith('/testing/completion')) return reply(decisionReview(saved))
    return reply(testingData(['Completed']))
  })
  vi.stubGlobal('fetch', fetcher)
  render(<TestingPage assessmentId={assessmentId} onExpired={expired} csrfToken="synthetic-csrf" />)
  await screen.findByRole('table')
  fireEvent.click(screen.getByRole('tab', { name: /Recommendations/ }))
  await screen.findByText('Pending Review')
  fireEvent.click(screen.getByRole('tab', { name: 'Testing Completion' }))
  fireEvent.click(await screen.findByRole('button', { name: requested === 'Reviewed' ? 'Mark reviewed' : 'Defer' }))
  expect(screen.queryByText('Reviewed')).not.toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Mark reviewed' })).toBeDisabled()
  await act(async () => { finish() })
  fireEvent.click(screen.getByRole('tab', { name: /Recommendations/ }))
  expect(await screen.findByText(outcome === 'failed' ? 'Pending Review' : requested)).toBeVisible()
  fireEvent.click(screen.getByRole('tab', { name: 'Testing Completion' }))
  const complete = await screen.findByRole('button', { name: 'Complete Testing' })
  if (outcome !== 'failed' && requested === 'Reviewed') expect(complete).toBeEnabled()
  else expect(complete).toBeDisabled()
  const write = fetcher.mock.calls.find(([url]) => String(url).endsWith('/completion/decisions'))!
  expect(write[1]?.headers).toMatchObject({ 'X-CSRF-Token': 'synthetic-csrf' })
  expect(JSON.parse(write[1]!.body as string)).toEqual({ recommendation_id: 'a'.repeat(64), decision: requested })
  expect(fetcher.mock.calls.filter(([url]) => String(url).endsWith('/completion/decisions'))).toHaveLength(1)
  expect(fetcher.mock.calls.filter(([url]) => String(url).endsWith('/start'))).toHaveLength(0)
})

it('ignores a late recommendation response after tab re-entry', async () => {
  let resolveOld: (value: ReturnType<typeof reply>) => void = () => { throw new Error('Old request not started') }
  let reads = 0
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    if (!String(input).endsWith('/recommendations')) return reply(testingData(['Completed']))
    reads += 1
    if (reads === 1) return new Promise<ReturnType<typeof reply>>(resolve => { resolveOld = resolve })
    return reply(recommendationData('Reviewed'))
  }))
  page()
  await screen.findByRole('table')
  fireEvent.click(screen.getByRole('tab', { name: /Recommendations/ }))
  expect(reads).toBe(1)
  fireEvent.click(screen.getByRole('tab', { name: 'Test Activity' }))
  fireEvent.click(screen.getByRole('tab', { name: /Recommendations/ }))
  expect(await screen.findByText('Reviewed')).toBeVisible()
  await act(async () => { resolveOld(reply(recommendationData())) })
  expect(screen.getByText('Reviewed')).toBeVisible()
  expect(screen.queryByText('Pending Review')).not.toBeInTheDocument()
})

it('polls persisted decision changes without granting execution rights', async () => {
  let decision: 'Deferred' | 'Reviewed' = 'Deferred'
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => reply(String(input).endsWith('/recommendations')
    ? recommendationData(decision) : testingData(['Completed']))))
  page()
  await screen.findByRole('table')
  vi.useFakeTimers()
  fireEvent.click(screen.getByRole('tab', { name: /Recommendations/ }))
  await act(async () => { await Promise.resolve() })
  expect(screen.getByText('Deferred')).toBeVisible()
  decision = 'Reviewed'
  await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
  expect(screen.getByText('Reviewed')).toBeVisible()
  fireEvent.click(screen.getByRole('button', { name: 'Review Recommendation' }))
  expect(within(screen.getByRole('dialog')).getByRole('button', { name: 'Start Test' })).toBeDisabled()
})


it('uses only completion counters despite a conflicting polled Testing overview', async () => {
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => reply(String(input).endsWith('/testing/completion')
    ? completionReview() : testingData(['Running', 'Running']))))
  page()
  await screen.findByRole('table')
  fireEvent.click(screen.getByRole('tab', { name: 'Testing Completion' }))
  await screen.findByRole('heading', { name: 'Ready to complete' })
  expect(screen.getByRole('region', { name: 'Total Tests' })).toHaveTextContent('Total Tests1')
  expect(screen.getByRole('region', { name: 'In Progress' })).toHaveTextContent('In Progress0')
  expect(screen.getByRole('region', { name: 'Completed' })).toHaveTextContent('Completed1')
})

it('retains an uncertain completion operation across real Testing tab changes', async () => {
  const fetcher = vi.fn(async (input: RequestInfo | URL, options?: RequestInit) => {
    const url = String(input)
    if (url.endsWith('/testing/completion')) {
      if (options?.method === 'POST') throw new Error('Lost completion response')
      return reply(completionReview())
    }
    return reply(url.endsWith('/recommendations') ? recommendationData() : testingData(['Completed']))
  })
  vi.stubGlobal('fetch', fetcher)
  render(<TestingPage assessmentId={assessmentId} csrfToken="synthetic-csrf" onExpired={expired} />)
  await screen.findByRole('table')
  fireEvent.click(screen.getByRole('tab', { name: 'Testing Completion' }))
  fireEvent.click(await screen.findByRole('button', { name: 'Complete Testing' }))
  fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Complete Testing' }))
  await screen.findByRole('heading', { name: 'Completion outcome unverified' })
  fireEvent.click(screen.getByRole('tab', { name: 'Test Activity' }))
  await screen.findByRole('table')
  fireEvent.click(screen.getByRole('tab', { name: 'Testing Completion' }))
  await screen.findByRole('heading', { name: 'Ready to complete' })
  expect(screen.getByRole('button', { name: 'Complete Testing' })).toBeDisabled()
  expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1)
})

it.each([401, 403, 404])('clears an open recommendation when overview access is lost (%s)', async status => {
  vi.useFakeTimers()
  let allowed = true
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) =>
    String(input).endsWith('/recommendations') ? reply(recommendationData())
      : allowed ? reply(testingData(['Completed'])) : reply({}, status)))
  page()
  await act(async () => { await Promise.resolve(); await Promise.resolve() })
  fireEvent.click(screen.getByRole('tab', { name: /Recommendations/ }))
  await act(async () => { await Promise.resolve(); await Promise.resolve() })
  fireEvent.click(screen.getByRole('button', { name: 'Review Recommendation' }))
  expect(screen.getByRole('dialog')).toBeVisible()
  allowed = false
  await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  expect(screen.queryByRole('heading', { name: 'Review responding host' })).not.toBeInTheDocument()
  expect(screen.getByRole('alert')).toHaveTextContent(status === 401 ? 'session has ended' : 'Assessment unavailable')
})

it('loads the persisted Finding Review lifecycle and receipt after a full page reload', async () => {
  const overview = { ...testingData(['Completed']), lifecycle_status: 'Finding Review' }
  const fetcher = vi.fn<(input: RequestInfo | URL, options?: RequestInit) => Promise<ReturnType<typeof reply>>>(async input =>
    reply(String(input).endsWith('/completion') ? completedCompletionReview() : overview))
  vi.stubGlobal('fetch', fetcher)
  const first = page()
  await screen.findByRole('table')
  fireEvent.click(screen.getByRole('tab', { name: 'Testing Completion' }))
  expect(await screen.findByRole('heading', { name: 'Testing Completed' })).toBeVisible()
  expect(screen.queryByRole('button', { name: 'Complete Testing' })).not.toBeInTheDocument()
  first.unmount()
  page()
  await screen.findByRole('table')
  fireEvent.click(screen.getByRole('tab', { name: 'Testing Completion' }))
  expect(await screen.findByRole('heading', { name: 'Testing Completed' })).toBeVisible()
  expect(fetcher.mock.calls.every(([, options]) => !options?.method)).toBe(true)
})

it.each(['Accepted', 'Rejected'] as const)('records %s only after server confirmation and readback, without execution', async outcome => {
  let persisted: 'Accepted' | 'Rejected' | null = null
  const fetcher = vi.fn<(input: RequestInfo | URL, options?: RequestInit) => Promise<ReturnType<typeof reply>>>(async (input, options) => {
    const url = String(input)
    if (url.endsWith('/decisions')) {
      const body = JSON.parse(String(options?.body))
      expect(body).toEqual({recommendation_id: 'a'.repeat(64), decision: 'Reviewed', review_outcome: outcome})
      expect(new Headers(options?.headers).get('x-csrf-token')).toBe('synthetic-csrf')
      persisted = outcome
      return reply({assessment_id: assessmentId, recommendation_id:'a'.repeat(64),decision:'Reviewed'})
    }
    return reply(url.endsWith('/recommendations') ? intelligentRecommendationData(persisted) : testingData(['Completed']))
  })
  vi.stubGlobal('fetch',fetcher)
  render(<TestingPage assessmentId={assessmentId} csrfToken="synthetic-csrf" onExpired={expired} />)
  await screen.findByRole('table')
  fireEvent.click(screen.getByRole('tab',{name:/Recommendations/}))
  fireEvent.click(await screen.findByRole('button',{name:'Review Recommendation'}))
  const dialog=screen.getByRole('dialog')
  expect(within(dialog).getByText('Assess an evidenced HTTP server.')).toBeVisible()
  expect(within(dialog).getByText(/Integration pending/)).toBeVisible()
  expect(within(dialog).getAllByText(/192.0.2.1/).length).toBeGreaterThan(0)
  expect(fetcher.mock.calls.every(([,options])=>!options?.method)).toBe(true)
  fireEvent.click(within(dialog).getByRole('button',{name:outcome==='Accepted'?'Accept':'Reject'}))
  expect(await screen.findByText(outcome)).toBeVisible()
  expect(fetcher.mock.calls.filter(([,options])=>options?.method==='POST')).toHaveLength(1)
  expect(fetcher.mock.calls.some(([url])=>/\/start$|\/execute$/.test(String(url)))).toBe(false)
})

it('keeps a meaningful pending-integration proposal visible without CSRF or execution permission', async () => {
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => reply(String(input).endsWith('/recommendations')
    ? intelligentRecommendationData() : testingData(['Completed']))))
  page();await screen.findByRole('table')
  fireEvent.click(screen.getByRole('tab',{name:/Recommendations/}))
  fireEvent.click(await screen.findByRole('button',{name:'Review Recommendation'}))
  const dialog=screen.getByRole('dialog')
  expect(within(dialog).getByRole('button',{name:'Accept'})).toBeDisabled()
  expect(within(dialog).getByRole('button',{name:'Reject'})).toBeDisabled()
  expect(within(dialog).queryByRole('button',{name:'Start Test'})).not.toBeInTheDocument()
  fireEvent.click(within(dialog).getByRole('button',{name:'Choose Alternative'}))
  expect(within(dialog).getByRole('button',{name:'Confirm Alternative'})).toBeDisabled()
})

it('does not retry an uncertain Accept or submit duplicate review writes', async () => {
  let rejectWrite!: (reason: Error) => void
  const fetcher=vi.fn<(input: RequestInfo | URL, options?: RequestInit) => Promise<ReturnType<typeof reply>>>((input,options) => {
    if(options?.method==='POST') return new Promise((_,reject)=>{rejectWrite=reject})
    return Promise.resolve(reply(String(input).endsWith('/recommendations') ? intelligentRecommendationData() : testingData(['Completed'])))
  })
  vi.stubGlobal('fetch',fetcher)
  render(<TestingPage assessmentId={assessmentId} csrfToken="synthetic-csrf" onExpired={expired} />)
  await screen.findByRole('table');fireEvent.click(screen.getByRole('tab',{name:/Recommendations/}))
  fireEvent.click(await screen.findByRole('button',{name:'Review Recommendation'}))
  const dialog=screen.getByRole('dialog');const accept=within(dialog).getByRole('button',{name:'Accept'})
  fireEvent.click(accept);fireEvent.click(accept)
  expect(fetcher.mock.calls.filter(([,options])=>options?.method==='POST')).toHaveLength(1)
  await act(async()=>rejectWrite(new Error('lost response')))
  expect(await within(dialog).findByRole('alert')).toHaveTextContent('unverified')
  expect(within(dialog).getByRole('button',{name:'Accept'})).toBeDisabled()
  expect(fetcher.mock.calls.filter(([,options])=>options?.method==='POST')).toHaveLength(1)
})

it('shows a later Deferred decision rather than a historical Accepted outcome', async () => {
  const value=intelligentRecommendationData('Accepted')
  value.recommendations[0].decision='Deferred'
  value.decision_counts={total:1,pending_review:0,reviewed:0,deferred:1,pending_completion:1}
  vi.stubGlobal('fetch',vi.fn(async(input: RequestInfo | URL)=>reply(String(input).endsWith('/recommendations')?value:testingData(['Completed']))))
  page();await screen.findByRole('table');fireEvent.click(screen.getByRole('tab',{name:/Recommendations/}))
  expect(await screen.findByText('Deferred')).toBeVisible()
  expect(screen.queryByText('Accepted')).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button',{name:'Review Recommendation'}))
  expect(within(screen.getByRole('dialog')).getByText('Deferred')).toBeVisible()
})

it('displays evidence-backed service observations without enabling pending tools', async () => {
  const overview = testingData(['Completed'])
  overview.executions[0] = { ...overview.executions[0], profile_id: 'service-discovery', profile_version: 1, test_name: 'Service Discovery' }
  overview.discovered_so_far = [{ id: 'service-fact', execution_id: overview.executions[0].id,
    target_id: overview.executions[0].target_id, type: 'service_discovery', partial: false,
    data: { address: '192.0.2.1', port: 443, state: 'open', transport: 'tcp', service: 'https', version: '1.2' } }]
  const details = executionDetails()
  details.test_name = 'Service Discovery'
  details.profile_id = 'service-discovery'
  details.observations = [{ ...overview.discovered_so_far[0], evidence_id: 'verified-evidence' }]
  vi.stubGlobal('fetch', vi.fn(async (url: string) => reply(url.endsWith('/testing') ? overview : details)))
  page()
  expect(await screen.findByText('192.0.2.1:443 · TCP open · HTTPS · 1.2')).toBeVisible()
  expect(screen.getByText('Recorded discovery observations are listed below. A detected service does not establish a web application or vulnerability.')).toBeVisible()
  fireEvent.click(screen.getByRole('button', { name: /View Details: Service Discovery/ }))
  expect(await screen.findByRole('dialog')).toBeVisible()
  const table = await within(screen.getByRole('dialog')).findByRole('table', { name: 'Discovered ports and services' })
  expect(within(table).getByText('443/tcp')).toBeVisible()
  expect(within(table).getByText('HTTPS')).toBeVisible()
  expect(within(table).getByText('1.2')).toBeVisible()
})

it('preserves T-01 monitoring without an additional service scheduling card or POST', async () => {
  const data = { ...testingData(['Completed']), can_schedule_service_discovery: true }
  const fetcher = vi.fn(async (url: string) => {
    if (url.endsWith('/testing')) return reply(data)
    throw new Error('Unexpected request')
  })
  vi.stubGlobal('fetch', fetcher)
  render(<TestingPage assessmentId={assessmentId} onExpired={expired} csrfToken="csrf" />)
  expect(await screen.findByRole('table', { name: 'Test Activity' })).toBeVisible()
  expect(screen.queryByRole('region', { name: 'Nmap Service Discovery' })).not.toBeInTheDocument()
  expect(screen.queryByRole('heading', { name: 'Nmap Service Discovery' })).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Schedule Service Discovery' })).not.toBeInTheDocument()
  expect(screen.queryByText(/No saved receipt is visible yet/)).not.toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Run Manual Test' })).toBeDisabled()
  expect(fetcher.mock.calls.every(([url]) => url.endsWith('/testing'))).toBe(true)
})

it('displays authoritative discovery totals, scope and authorization identity without fabricated web targets', async () => {
  const data = testingData(['Completed'])
  data.discovery_totals = { open_ports: 2, services: 2, web_targets: null }
  data.authorization_scope.boundaries = [{ value: '192.0.2.0/24', kind: 'Subnet' }]
  data.authorization_scope.authorized_by = { id: 'actor', username: 'analyst-real', confirmed_at: '2026-11-20T10:00:00Z' }
  vi.stubGlobal('fetch', vi.fn(async () => reply(data)))
  page()
  expect(await screen.findByText('192.0.2.0/24')).toBeVisible()
  expect(screen.getByText(/analyst-real/)).toBeVisible()
  for (const label of ['Open ports', 'Services']) expect(screen.getByText(label).previousElementSibling).toHaveTextContent('2')
  expect(screen.getByText('Web target').previousElementSibling).toHaveTextContent('—')
  expect(screen.queryByText('Not provided by the Testing API.')).not.toBeInTheDocument()
})


it.each(['Queued', 'Running', 'Completed', 'Failed', 'Blocked'] as ExecutionStatus[])(
  'displays a persisted recommended %s job without inventing Nmap observations', async status => {
    const overview = testingData([status])
    Object.assign(overview.executions[0], { tool: 'Nikto', test_name: 'HTTP Server Assessment',
      profile_id: 'nikto-http-service-restricted', execution_kind: 'recommended', authorization_id: null })
    const detail = { ...executionDetails(), ...overview.executions[0], execution_kind: 'recommended',
      recommended_result: { termination_verified: status === 'Completed' || status === 'Failed',
        integrity_verified: status === 'Completed' || status === 'Failed', partial: status !== 'Completed',
        failure_reason: status === 'Failed' ? 'scanner_failed' : null } }
    const fetcher = vi.fn(async (input: RequestInfo | URL) => reply(String(input).endsWith('/synthetic-execution-0') ? detail : overview))
    vi.stubGlobal('fetch', fetcher)
    page()
    fireEvent.click(await screen.findByRole('button', { name: /View Details:/ }))
    const dialog = await screen.findByRole('dialog')
    expect(await within(dialog).findByText('Tool: Nikto')).toBeVisible()
    expect(within(dialog).getByText(status, { selector: 'span' })).toBeVisible()
    expect(within(dialog).getByText(/No normalized findings are asserted/)).toBeVisible()
    expect(within(dialog).queryByText(/Host reachability alone/)).not.toBeInTheDocument()
    if (status === 'Failed') expect(within(dialog).getByText('scanner_failed')).toBeVisible()
    if (status === 'Blocked') expect(within(dialog).queryByText(/completion cannot be verified/)).not.toBeInTheDocument()
  })
