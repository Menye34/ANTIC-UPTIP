import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
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
  execution_authorized: false, authorized_activity_count: 1,
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
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  if (originalShowModal) Object.defineProperty(HTMLDialogElement.prototype, 'showModal', originalShowModal)
  else Reflect.deleteProperty(HTMLDialogElement.prototype, 'showModal')
  if (originalClose) Object.defineProperty(HTMLDialogElement.prototype, 'close', originalClose)
  else Reflect.deleteProperty(HTMLDialogElement.prototype, 'close')
})

it('accepts Testing, preserves exclusions and submits session CSRF and explicit confirmation', async () => {
  const fetcher = vi.fn(async (input: RequestInfo | URL, options?: RequestInit) => {
    const url = String(input)
    if (url.endsWith('/start')) {
      expect(options?.credentials).toBe('same-origin')
      expect(options?.headers).toMatchObject({ 'X-CSRF-Token': 'csrf', 'Idempotency-Key': expect.any(String) })
      expect(JSON.parse(String(options?.body))).toEqual({
        review_token: 'review-token', mode: 'partial', confirmed: true,
      })
      return response(receipt, 201)
    }
    if (url.endsWith('/readiness')) return response({ start_review: startReview })
    return response({ status: 'Draft', can_edit: true, targets: [], counts: { total: 0, eligible: 0, blocked: 0 } })
  })
  vi.stubGlobal('fetch', fetcher)
  render(<AssessmentTargets overview={'/analyst/assessments/' + id} csrfToken="csrf" onExpired={vi.fn()} />)
  const start = await screen.findByRole('button', { name: 'Start Assessment' })
  await waitFor(() => expect(start).toBeEnabled())
  fireEvent.click(start)
  expect(await screen.findByText(/Outside authorized scope/)).toBeVisible()
  fireEvent.click(screen.getByRole('button', { name: 'Confirm Start Assessment' }))
  expect(await screen.findByText('Assessment Testing')).toBeVisible()
  expect(screen.getByText(/1 baseline activities queued/)).toBeVisible()
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
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    if (String(input).endsWith('/start')) return response({ ...receipt, assessment_id: 'other-assessment' }, 201)
    if (String(input).endsWith('/readiness')) return response({ start_review: startReview })
    return response({ status: 'Draft', can_edit: true, targets: [], counts: { total: 0, eligible: 0, blocked: 0 } })
  }))
  render(<AssessmentTargets overview={'/analyst/assessments/' + id} csrfToken="csrf" onExpired={vi.fn()} />)
  const start = await screen.findByRole('button', { name: 'Start Assessment' })
  await waitFor(() => expect(start).toBeEnabled())
  fireEvent.click(start)
  fireEvent.click(await screen.findByRole('button', { name: 'Confirm Start Assessment' }))
  expect(await screen.findByText(/confirmation outcome is unknown/)).toBeVisible()
  expect(start).toBeDisabled()
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
