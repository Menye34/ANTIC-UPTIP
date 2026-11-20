import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import AssessmentTargets from './AssessmentTargets'
import { assessmentTestingPath } from '../services/assessmentStart'

const id = 'test-assessment'
const eligible = { target_id: 'target', profile_id: 'network-discovery', tool: 'Nmap', activity: 'Network Discovery' }
const startReview = {
  confirmation_possible: true, mode: 'partial', review_token: 'review-token',
  expires_at: new Date(Date.now() + 600000).toISOString(),
  eligible_activities: [eligible], excluded_activities: [],
  excluded_targets: [{ target_id: 'outside', reasons: [{ code: 'outside_scope', message: 'Outside authorized scope' }] }],
}
const receipt = {
  assessment_id: id, authorization_id: 'authorization', lifecycle_status: 'Testing',
  queued_execution_count: 1, queued_execution_ids: ['queued-1'],
  testing_url: '/api/v1/assessments/' + id + '/testing',
  execution_authorized: false, authorized_activity_count: 1, authorized_target_count: 1,
  excluded_activities: [], excluded_targets: startReview.excluded_targets,
  excluded_activity_count: 0, excluded_target_count: 1, mode: 'partial',
  confirmed_at: '2026-11-13T12:00:00Z',
}
const targets = [
  { id: 'target', original_value: '192.0.2.1', normalized_value: '192.0.2.1',
    kind: 'IP address', scope_status: 'in_scope', eligibility: 'pending', revision: 1,
    classification_reason: 'Contained in authorized subnet.', scope_revision: 1,
    created_at: '2026-11-13T11:00:00Z', updated_at: '2026-11-13T11:00:00Z',
    baseline_summary: 'resolved', baseline_assignments: [{ profile_id: 'network-discovery',
      version: 1, tool: 'Nmap', activity: 'Network Discovery', status: 'resolved',
      reason_code: 'prepared', reason: 'Baseline prepared for review.' }] },
  { id: 'outside', original_value: '198.51.100.1', normalized_value: '198.51.100.1',
    kind: 'IP address', scope_status: 'out_of_scope', eligibility: 'blocked', revision: 1,
    classification_reason: 'Outside authorized scope.', scope_revision: 1,
    created_at: '2026-11-13T11:00:00Z', updated_at: '2026-11-13T11:00:00Z',
    baseline_summary: 'blocked', baseline_assignments: [{ profile_id: 'network-discovery',
      version: 1, tool: 'Nmap', activity: 'Network Discovery', status: 'blocked',
      reason_code: 'outside_scope', reason: 'Target is outside the authorized scope.' }] },
]
function targetList(status = 'Draft') {
  return { status, can_edit: status === 'Draft', targets, counts: { total: 2, eligible: 0, blocked: 1 } }
}
function readinessResponse(review = startReview, lifecycle = 'Draft') {
  return { assessment_id: id, lifecycle_status: lifecycle, reasons: [],
    start_review_eligible: review.confirmation_possible, start_review: review, targets: [],
    execution_authorized: false }
}
function testingOverview(changes: Partial<Record<'queued' | 'in_progress' | 'completed' | 'failed' | 'stopped' | 'blocked' | 'cancelled', number>> = { queued: 1 }) {
  const counts = { queued: 0, in_progress: 0, completed: 0, failed: 0, stopped: 0, blocked: 0, cancelled: 0, ...changes }
  const names = { queued: 'Queued', in_progress: 'Running', completed: 'Completed', failed: 'Failed', stopped: 'Stopped', blocked: 'Blocked', cancelled: 'Cancelled' }
  return { assessment_id: id, lifecycle_status: 'Testing',
    counts: { ...counts, total: Object.values(counts).reduce((a, b) => a + b, 0) },
    executions: Object.entries(counts).flatMap(([state, count]) => Array.from({ length: count }, (_, index) => ({
      id: state + index, target_id: 'target', profile_id: 'network-discovery', profile_version: 1,
      test_name: 'Network Discovery', tool: 'Nmap', target: '192.0.2.1', status: names[state as keyof typeof names],
      authorization_id: 'authorization', created_at: receipt.confirmed_at, updated_at: receipt.confirmed_at,
      execution_authorized: false,
    }))),
    authorization_scope: { authorization_id: 'authorization', scope_revision: 1, scope_digest: 'a'.repeat(64),
      mode: 'partial', policy: { id: 'uptip-baseline-scheduling', version: 1, purpose: 'schedule_only' },
      excluded_activities: [], excluded_targets: startReview.excluded_targets },
    discovered_so_far: [], recent_activity: [],
  }
}
function expectNoDraftActions() {
  expect(screen.queryByRole('button', { name: 'Start Assessment' })).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Confirm Start Assessment' })).not.toBeInTheDocument()
  expect(screen.queryByRole('dialog', { name: 'Confirm Start Assessment' })).not.toBeInTheDocument()
  expect(screen.queryByText('Start Assessment is currently blocked.')).not.toBeInTheDocument()
  expect(screen.queryByText('Only Draft assessments can be started.')).not.toBeInTheDocument()
  expect(screen.queryByText('No activity is eligible for queued scheduling.')).not.toBeInTheDocument()
}
function count(label: string) {
  return screen.getByText(label, { selector: 'dt' }).nextElementSibling
}
function response(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } })
}
const originalShowModal = Object.getOwnPropertyDescriptor(HTMLDialogElement.prototype, 'showModal')
const originalClose = Object.getOwnPropertyDescriptor(HTMLDialogElement.prototype, 'close')
beforeEach(() => {
  Object.defineProperty(HTMLDialogElement.prototype, 'showModal', {
    configurable: true, value(this: HTMLDialogElement) { this.setAttribute('open', '') },
  })
  Object.defineProperty(HTMLDialogElement.prototype, 'close', {
    configurable: true, value(this: HTMLDialogElement) { this.removeAttribute('open') },
  })
})
afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  if (originalShowModal) Object.defineProperty(HTMLDialogElement.prototype, 'showModal', originalShowModal)
  else Reflect.deleteProperty(HTMLDialogElement.prototype, 'showModal')
  if (originalClose) Object.defineProperty(HTMLDialogElement.prototype, 'close', originalClose)
  else Reflect.deleteProperty(HTMLDialogElement.prototype, 'close')
})

it.each([false, true])('accepts Testing and preserves confirmed Start when navigation fails: %s', async navigationFails => {
  const navigate = vi.fn(() => { if (navigationFails) throw new Error('synthetic-navigation-failure') })
  let started = false
  const fetcher = vi.fn(async (input: RequestInfo | URL, options?: RequestInit) => {
    const url = String(input)
    if (url.endsWith('/start')) {
      expect(options?.credentials).toBe('same-origin')
      expect(options?.headers).toMatchObject({ 'X-CSRF-Token': 'csrf', 'Idempotency-Key': expect.any(String) })
      expect(JSON.parse(String(options?.body))).toEqual({
        review_token: 'review-token', mode: 'partial', confirmed: true,
      })
      started = true
      return response(receipt, 201)
    }
    if (url.endsWith('/readiness')) return response(readinessResponse())
    if (url.endsWith('/testing')) {
      expect(options?.credentials).toBe('same-origin')
      expect(options?.cache).toBe('no-store')
      return response(testingOverview())
    }
    return response(targetList(started ? 'Testing' : 'Draft'))
  })
  vi.stubGlobal('fetch', fetcher)
  render(<AssessmentTargets overview={'/analyst/assessments/' + id} csrfToken="csrf" onExpired={vi.fn()} navigate={navigate} />)
  const start = await screen.findByRole('button', { name: 'Start Assessment' })
  await waitFor(() => expect(start).toBeEnabled())
  expect(screen.getByText('In-scope targets')).toBeVisible()
  expect(screen.getByText(/1 targets eligible for scheduling; 1 targets excluded from Start/)).toBeVisible()
  fireEvent.click(start)
  expect(await screen.findByText(/Outside authorized scope/)).toBeVisible()
  fireEvent.click(screen.getByRole('button', { name: 'Confirm Start Assessment' }))
  expect(await screen.findByRole('heading', { name: 'Assessment Started' })).toBeVisible()
  expect(await screen.findByRole('heading', { name: 'Assessment Started' })).toBeVisible()
  expect(navigate).toHaveBeenCalledExactlyOnceWith(assessmentTestingPath(id))
  expect(count('Included targets')).toHaveTextContent('1')
  expect(count('Excluded targets')).toHaveTextContent('1')
  expect(screen.getByRole('link', { name: 'Go to Testing' })).toHaveAttribute('href', expect.stringContaining('/testing'))
  expect(screen.queryByText('Latest retrieved execution status')).not.toBeInTheDocument()
  expectNoDraftActions()
  expect(screen.getAllByText('Nmap · Network Discovery · v1')).toHaveLength(2)
  fireEvent.click(start)
  expect(fetcher.mock.calls.filter(([url]) => String(url).endsWith('/start'))).toHaveLength(1)
  expect(assessmentTestingPath(id)).toBe('/analyst/assessments/test-assessment/testing')
})

it('refreshes readiness after a stale Start response', async () => {
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    if (String(input).endsWith('/start')) return response({ detail: { code: 'start_review_stale' } }, 409)
    if (String(input).endsWith('/readiness')) return response({ start_review: startReview })
    return response({ status: 'Draft', can_edit: true, targets: [], counts: { total: 0, eligible: 0, blocked: 0 } })
  }))
  render(<AssessmentTargets overview={'/analyst/assessments/' + id} csrfToken="csrf" onExpired={vi.fn()} />)
  const start = await screen.findByRole('button', { name: 'Start Assessment' })
  await waitFor(() => expect(start).toBeEnabled())
  fireEvent.click(start)
  fireEvent.click(await screen.findByRole('button', { name: 'Confirm Start Assessment' }))
  expect(await screen.findByText(/review is no longer valid/)).toBeVisible()
  expect(screen.queryByText('Assessment Testing')).not.toBeInTheDocument()
})

it('blocks an expired review while preserving the existing blocked Start UI', async () => {
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    if (String(input).endsWith('/readiness')) {
      return response({ start_review: { ...startReview, expires_at: new Date(Date.now() - 1000).toISOString() } })
    }
    return response({ status: 'Draft', can_edit: true, targets: [], counts: { total: 0, eligible: 0, blocked: 0 } })
  }))
  render(<AssessmentTargets overview={'/analyst/assessments/' + id} csrfToken="csrf" onExpired={vi.fn()} />)
  await screen.findByText(/activities eligible for Start authorization/)
  expect(screen.getByRole('button', { name: 'Start Assessment' })).toBeDisabled()
})

it('treats an invalid success receipt as an uncertain outcome and prevents another Start', async () => {
  const navigate = vi.fn()
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    if (String(input).endsWith('/start')) return response({ ...receipt, assessment_id: 'other-assessment' }, 201)
    if (String(input).endsWith('/readiness')) return response({ start_review: startReview })
    return response({ status: 'Draft', can_edit: true, targets: [], counts: { total: 0, eligible: 0, blocked: 0 } })
  }))
  render(<AssessmentTargets overview={'/analyst/assessments/' + id} csrfToken="csrf" onExpired={vi.fn()} navigate={navigate} />)
  const start = await screen.findByRole('button', { name: 'Start Assessment' })
  await waitFor(() => expect(start).toBeEnabled())
  fireEvent.click(start)
  fireEvent.click(await screen.findByRole('button', { name: 'Confirm Start Assessment' }))
  expect(await screen.findByText(/confirmation outcome is unknown/)).toBeVisible()
  expect(start).toBeDisabled()
  expect(navigate).not.toHaveBeenCalled()
})

it('refreshes an expired review without bypassing backend eligibility', async () => {
  let checks = 0
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    if (String(input).endsWith('/readiness')) {
      checks++
      return response({ start_review: { ...startReview,
        expires_at: new Date(Date.now() + (checks === 1 ? -1000 : 600000)).toISOString() } })
    }
    return response({ status: 'Draft', can_edit: true, targets: [], counts: { total: 0, eligible: 0, blocked: 0 } })
  }))
  render(<AssessmentTargets overview={'/analyst/assessments/' + id} csrfToken="csrf" onExpired={vi.fn()} />)
  expect(await screen.findByText(/Start review has expired/)).toBeVisible()
  expect(screen.getByRole('button', { name: 'Start Assessment' })).toBeDisabled()
  fireEvent.click(screen.getByRole('button', { name: 'Refresh readiness' }))
  await waitFor(() => expect(screen.getByRole('button', { name: 'Start Assessment' })).toBeEnabled())
  expect(checks).toBe(2)
})

it('renders backend blocker messages and excluded-target reasons without inventing eligibility', async () => {
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    if (String(input).endsWith('/readiness')) return response({
      reasons: [{ code: 'system_authorization_unverified', message: 'System authorization is not valid.' }],
      start_review: { ...startReview, confirmation_possible: false, mode: null, review_token: null,
        expires_at: null, eligible_activities: [], excluded_activities: [{ ...eligible,
          exclusion_code: 'activity_parameters_unverified',
          policy: { reason_code: 'activity_parameters_unverified', reason: 'Activity parameters are unverified.' } }],
      },
    })
    return response({ status: 'Draft', can_edit: true, targets: [], counts: { total: 0, eligible: 0, blocked: 0 } })
  }))
  render(<AssessmentTargets overview={'/analyst/assessments/' + id} csrfToken="csrf" onExpired={vi.fn()} />)
  expect(await screen.findByText('System authorization is not valid.')).toBeVisible()
  expect(screen.getByText(/Activity parameters are unverified/)).toBeVisible()
  expect(screen.getByText('Outside authorized scope')).toBeVisible()
  expect(screen.getByRole('button', { name: 'Start Assessment' })).toBeDisabled()
})

it('loads persisted Testing state without requesting Draft readiness or execution monitoring', async () => {
  const fetcher = vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    if (url.endsWith('/targets')) return response(targetList('Testing'))
    throw new Error('Unexpected request: ' + url)
  })
  vi.stubGlobal('fetch', fetcher)
  render(<AssessmentTargets overview={'/analyst/assessments/' + id} csrfToken="csrf" onExpired={vi.fn()} />)
  expect(await screen.findByRole('heading', { name: 'Assessment Started' })).toBeVisible()
  expectNoDraftActions()
  expect(screen.getByText('Not recorded')).toBeVisible()
  expect(count('Included targets')).toHaveTextContent('Not available')
  expect(count('Excluded targets')).toHaveTextContent('Not available')
  expect(screen.getByRole('link', { name: 'Go to Testing' })).toHaveAttribute('href', expect.stringContaining('/testing'))
  expect(screen.queryByRole('button', { name: 'Refresh execution status' })).not.toBeInTheDocument()
  expect(screen.queryByText('Queued', { selector: 'dt' })).not.toBeInTheDocument()
  expect(fetcher.mock.calls.some(([url]) => String(url).endsWith('/readiness') || String(url).endsWith('/testing'))).toBe(false)
})

it('preserves confirmation counts without fetching live execution counters', async () => {
  let started = false
  const fetcher = vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    if (url.endsWith('/start')) { started = true; return response(receipt, 201) }
    if (url.endsWith('/readiness')) return response(readinessResponse())
    if (url.endsWith('/targets')) return response(targetList(started ? 'Testing' : 'Draft'))
    throw new Error('Unexpected request: ' + url)
  })
  vi.stubGlobal('fetch', fetcher)
  render(<AssessmentTargets overview={'/analyst/assessments/' + id} csrfToken="csrf" onExpired={vi.fn()} />)
  await waitFor(() => expect(screen.getByRole('button', { name: 'Start Assessment' })).toBeEnabled())
  fireEvent.click(screen.getByRole('button', { name: 'Start Assessment' }))
  fireEvent.click(screen.getByRole('button', { name: 'Confirm Start Assessment' }))
  expect(await screen.findByRole('heading', { name: 'Assessment Started' })).toBeVisible()
  expect(count('Included targets')).toHaveTextContent('1')
  expect(count('Excluded targets')).toHaveTextContent('1')
  expectNoDraftActions()
  expect(fetcher.mock.calls.some(([url]) => String(url).endsWith('/testing'))).toBe(false)
})

it('handles readiness reporting an externally started assessment without Draft blockers', async () => {
  const fetcher = vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    if (url.endsWith('/readiness')) return response({ ...readinessResponse(), lifecycle_status: 'Testing',
      reasons: [{ code: 'lifecycle_not_draft', message: 'Only Draft assessments can be started.' }],
      start_review: { ...startReview, confirmation_possible: false, mode: null, review_token: null,
        eligible_activities: [], excluded_targets: [] } })
    if (url.endsWith('/targets')) return response(targetList())
    throw new Error('Unexpected request: ' + url)
  })
  vi.stubGlobal('fetch', fetcher)
  render(<AssessmentTargets overview={'/analyst/assessments/' + id} csrfToken="csrf" onExpired={vi.fn()} />)
  expect(await screen.findByRole('heading', { name: 'Assessment Started' })).toBeVisible()
  expectNoDraftActions()
  expect(fetcher.mock.calls.some(([url]) => String(url).endsWith('/testing'))).toBe(false)
})

it('prevents duplicate confirmations while Start is pending and removes the confirmation action on success', async () => {
  let complete: (result: Response) => void = () => { throw new Error('No Start request') }
  const fetcher = vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    if (url.endsWith('/start')) return new Promise<Response>(resolve => { complete = resolve })
    if (url.endsWith('/readiness')) return response(readinessResponse())
    if (url.endsWith('/testing')) return response(testingOverview())
    return response(targetList())
  })
  vi.stubGlobal('fetch', fetcher)
  render(<AssessmentTargets overview={'/analyst/assessments/' + id} csrfToken="csrf" onExpired={vi.fn()} />)
  await waitFor(() => expect(screen.getByRole('button', { name: 'Start Assessment' })).toBeEnabled())
  fireEvent.click(screen.getByRole('button', { name: 'Start Assessment' }))
  const button = screen.getByRole('button', { name: 'Confirm Start Assessment' })
  fireEvent.click(button)
  fireEvent.click(button)
  expect(button).toBeDisabled()
  expect(fetcher.mock.calls.filter(([url]) => String(url).endsWith('/start'))).toHaveLength(1)
  await act(async () => { complete(response(receipt, 201)) })
  expectNoDraftActions()
})

it('shows the exact authorized service target and ports in the existing Start confirmation', async () => {
  const service = { target_id: 'target', profile_id: 'service-discovery', tool: 'Nmap', activity: 'Service Discovery',
    scheduling_preparation: { target_value: '192.0.2.1', authorized_tcp_ports: [80, 443] } }
  const review = { ...startReview, eligible_activities: [eligible, service] }
  const fetcher = vi.fn(async (input: RequestInfo | URL) => String(input).endsWith('/readiness')
    ? response(readinessResponse(review)) : response(targetList()))
  vi.stubGlobal('fetch', fetcher)
  render(<AssessmentTargets overview={'/analyst/assessments/' + id} csrfToken="csrf" onExpired={vi.fn()} />)
  const start = await screen.findByRole('button', { name: 'Start Assessment' })
  await waitFor(() => expect(start).toBeEnabled())
  fireEvent.click(start)
  expect(await screen.findByText(/192\.0\.2\.1, TCP 80, 443/)).toBeVisible()
  expect(screen.getByText('Service Discovery', { exact: false, selector: 'li' })).toBeVisible()
  expect(fetcher.mock.calls.some(([url]) => String(url).endsWith('/start'))).toBe(false)
})
