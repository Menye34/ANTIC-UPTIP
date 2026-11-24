import { useState } from 'react'
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import TestingCompletion from './TestingCompletion'
import type { CompletionOperation } from './TestingCompletion'
import { assessmentId, completedCompletionReview, completionReview } from '../test-fixtures/testing'
import type { CompletionReview } from '../services/testingCompletion'

const reply = (value: unknown, status = 200) => ({ ok: status < 400, status, json: async () => value })
const expired = vi.fn()
const decisionsChanged = vi.fn()
const showModal = Object.getOwnPropertyDescriptor(HTMLDialogElement.prototype, 'showModal')
const close = Object.getOwnPropertyDescriptor(HTMLDialogElement.prototype, 'close')
beforeEach(() => {
  expired.mockReset(); decisionsChanged.mockReset()
  Object.defineProperty(HTMLDialogElement.prototype, 'showModal', { configurable: true, value(this: HTMLDialogElement) { this.open = true } })
  Object.defineProperty(HTMLDialogElement.prototype, 'close', { configurable: true, value(this: HTMLDialogElement) { this.open = false } })
})
afterEach(() => {
  cleanup(); vi.useRealTimers(); vi.unstubAllGlobals()
  if (showModal) Object.defineProperty(HTMLDialogElement.prototype, 'showModal', showModal)
  else Reflect.deleteProperty(HTMLDialogElement.prototype, 'showModal')
  if (close) Object.defineProperty(HTMLDialogElement.prototype, 'close', close)
  else Reflect.deleteProperty(HTMLDialogElement.prototype, 'close')
})

function Harness({ csrf = 'synthetic-csrf', id = assessmentId }: { csrf?: string; id?: string }) {
  const [operation, setOperation] = useState<CompletionOperation>({ phase: 'idle' })
  const [show, setShow] = useState(true)
  return <>
    <button onClick={() => setShow(n => !n)}>Toggle completion</button>
    {show && <TestingCompletion assessmentId={id} csrfToken={csrf} operation={operation} onOperationChange={setOperation}
      onExpired={expired} onDecisionsChanged={decisionsChanged} onContinue={() => setShow(false)} onRecommendations={() => setShow(false)} />}
  </>
}
function setup(value = completionReview(), csrf?: string) {
  const fetcher = vi.fn<(input: RequestInfo | URL, options?: RequestInit) => Promise<ReturnType<typeof reply>>>(async () => reply(value))
  vi.stubGlobal('fetch', fetcher)
  const view = render(<Harness csrf={csrf} />)
  return { fetcher, ...view }
}
async function open() {
  const button = screen.queryByRole('button', { name: 'Complete Testing' })
    ?? await screen.findByRole('button', { name: 'Complete Testing' })
  expect(button).toBeEnabled()
  button.focus(); fireEvent.click(button)
  return screen.getByRole('dialog', { name: 'Complete testing?' })
}
function submit() { fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Complete Testing' })) }

it('renders four unknown metrics while readiness is loading, never zero or Clear', () => {
  vi.stubGlobal('fetch', vi.fn(() => new Promise(() => {})))
  render(<Harness />)
  for (const label of ['Total Tests', 'In Progress', 'Completed', 'Failed']) {
    expect(within(screen.getByRole('region', { name: label })).getByText('—')).toBeVisible()
  }
  expect(screen.queryByText('Clear')).not.toBeInTheDocument()
  expect(screen.getByRole('status')).toHaveTextContent('Checking completion readiness')
})

it('renders the completion snapshot in all metrics and exactly four review rows', async () => {
  setup()
  await screen.findByRole('heading', { name: 'Ready to complete' })
  expect(screen.getByRole('region', { name: 'Total Tests' })).toHaveTextContent('Total Tests1')
  expect(screen.getByRole('region', { name: 'In Progress' })).toHaveTextContent('In Progress0')
  expect(screen.getByRole('region', { name: 'Completed' })).toHaveTextContent('Completed1')
  expect(screen.getByRole('region', { name: 'Failed' })).toHaveTextContent('Failed0')
  expect(document.querySelectorAll('.testing-completion-check')).toHaveLength(4)
  expect(screen.getByText(/A verified candidate findings count is not available yet/)).toBeVisible()
})

it.each([false, true])('applies creator capability without changing factual readiness: creator=%s', async creator => {
  const value = completionReview(); value.can_complete = creator
  setup(value)
  expect(await screen.findByRole('heading', { name: 'Ready to complete' })).toBeVisible()
  const button = screen.getByRole('button', { name: 'Complete Testing' })
  if (creator) expect(button).toBeEnabled()
  else {
    expect(button).toBeDisabled()
    expect(screen.getByText(/Only the assessment creator can complete testing/)).toBeVisible()
  }
})

it('preserves CSRF requirement and does not open confirmation without a token', async () => {
  const { fetcher } = setup(completionReview(), '')
  const button = await screen.findByRole('button', { name: 'Complete Testing' })
  expect(button).toBeDisabled(); fireEvent.click(button)
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  expect(fetcher.mock.calls.every(([, options]) => !options?.method)).toBe(true)
})

it('counts one Running request and its attempt once, including recovery diagnostics', async () => {
  const value = completionReview()
  value.ready = false
  value.summary.counts.Completed = 0; value.summary.counts.Running = 1
  value.summary.active_execution_requests = value.summary.active_attempts = value.summary.recovery_required_requests = 1
  value.summary.blockers = ['active_tests']
  value.blocker_details = [{ code: 'active_tests', message: 'Active request remains.', count: 1, action: 'view_tests' }]
  setup(value)
  expect(await screen.findByText('1 active or queued test activities remain.')).toBeVisible()
  expect(screen.queryByText('2 active or queued test activities remain.')).not.toBeInTheDocument()
  expect(screen.getByText('1 execution request(s) require recovery verification.')).toBeVisible()
  expect(screen.getByRole('region', { name: 'In Progress' })).toHaveTextContent('In Progress1')
  expect(screen.getByRole('button', { name: 'Complete Testing' })).toBeDisabled()
})

it.each(['Deferred', 'processing', 'unsuccessful'] as const)('keeps %s work visible and blocking', async kind => {
  const value = completionReview(); value.ready = false
  if (kind === 'Deferred') {
    value.recommendations = [{ id: 'a'.repeat(64), title: 'Review responding host', decision: 'Deferred' }]
    value.summary.recommendation_count = value.summary.deferred_recommendations = 1
    value.summary.pending_recommendation_ids = ['a'.repeat(64)]
    value.summary.decision_counts = { total: 1, reviewed: 0, pending_review: 0, deferred: 1, pending_completion: 1 }
    value.summary.blockers = ['pending_recommendations']
  } else if (kind === 'processing') {
    value.summary.processing_errors = 1; value.summary.blockers = ['processing_not_clear']
  } else {
    value.summary.counts.Completed = 0; value.summary.counts.Failed = 1; value.summary.blockers = ['unsuccessful_tests']
  }
  value.blocker_details = value.summary.blockers.map(code => ({ code, message: 'Review required.', count: 1, action: null }))
  setup(value)
  await screen.findByRole('heading', { name: 'Completion unavailable' })
  expect(screen.getByRole('button', { name: 'Complete Testing' })).toBeDisabled()
  if (kind === 'Deferred') expect(screen.getByText('1 deferred recommendation(s) still require review.')).toBeVisible()
  if (kind === 'processing') expect(screen.getByText(/1 processing issue/)).toBeVisible()
  if (kind === 'unsuccessful') expect(screen.getByText(/1 unsuccessful or interrupted tests/)).toBeVisible()
})

it.each(['cancel', 'escape'])('preserves ready state, assessment name and focus on %s', async action => {
  const { fetcher } = setup()
  const dialog = await open()
  expect(screen.getByRole('heading', { name: 'Ready to complete' })).toBeVisible()
  expect(within(dialog).getByText(/Synthetic Network Assessment/)).toBeVisible()
  expect(within(dialog).getByText('1 tests completed')).toBeVisible()
  if (action === 'cancel') fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
  else fireEvent(dialog, new Event('cancel', { bubbles: true, cancelable: true }))
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Complete Testing' })).toHaveFocus()
  expect(fetcher.mock.calls.every(([, options]) => !options?.method)).toBe(true)
})

it('captures a private snapshot, submits its digest once and immediately displays the receipt', async () => {
  const value = completionReview()
  let resolvePost: (value: ReturnType<typeof reply>) => void = () => { throw new Error('POST not started') }
  const fetcher = vi.fn(async (_input: RequestInfo | URL, options?: RequestInit) => {
    if (options?.method === 'POST') return new Promise<ReturnType<typeof reply>>(resolve => { resolvePost = resolve })
    return reply(value)
  })
  vi.stubGlobal('fetch', fetcher); render(<Harness />)
  const dialog = await open()
  // Mutating the old response object must not mutate the captured review.
  value.summary.counts.Completed = 999
  expect(within(dialog).getByText('1 tests completed')).toBeVisible()
  const button = within(dialog).getByRole('button', { name: 'Complete Testing' })
  await act(async () => { button.click(); button.click() })
  const posts = fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')
  expect(posts).toHaveLength(1)
  expect(JSON.parse(posts[0][1]!.body as string)).toEqual({ snapshot_digest: 'b'.repeat(64), confirmed: true })
  expect(posts[0][1]?.headers).toMatchObject({ 'X-CSRF-Token': 'synthetic-csrf' })
  await act(async () => { resolvePost(reply(completedCompletionReview())) })
  expect(await screen.findByRole('heading', { name: 'Testing Completed' })).toBeVisible()
  expect(screen.queryByRole('button', { name: 'Complete Testing' })).not.toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Continue to Findings' })).toBeDisabled()
  expect(fetcher).toHaveBeenCalledTimes(2) // initial GET and POST, no compulsory post-success GET
})

it.each(['digest', 'capability', 'blocker', 'unavailable'] as const)('invalidates confirmation when refresh changes %s', async kind => {
  const value = completionReview()
  let current: CompletionReview | undefined = value
  vi.stubGlobal('fetch', vi.fn(async () => current ? reply(current) : reply({}, 503)))
  vi.useFakeTimers()
  render(<Harness />)
  await act(async () => { await Promise.resolve() })
  await open()
  if (kind === 'unavailable') current = undefined
  else {
    current = structuredClone(value)
    if (kind === 'digest') current.snapshot_digest = 'd'.repeat(64)
    else if (kind === 'capability') current.can_complete = false
    else {
      current.ready = false; current.summary.processing_errors = 1; current.summary.blockers = ['processing_not_clear']
      current.blocker_details = [{ code: 'processing_not_clear', message: 'Processing issue.', count: 1, action: 'view_tests' }]
    }
  }
  await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  if (kind !== 'unavailable') expect(screen.getByRole('heading', { name: kind === 'blocker' ? 'Completion unavailable' : 'Ready to complete' })).toBeVisible()
  expect(screen.getByRole('alert')).toBeVisible()
})

it('retains confirmed success through refresh failure, contradictory Testing and a tab remount', async () => {
  let mode: 'ready' | 'done' | 'error' | 'stale' = 'ready'
  const fetcher = vi.fn(async (_input: RequestInfo | URL, options?: RequestInit) => {
    if (options?.method === 'POST') { mode = 'done'; return reply(completedCompletionReview()) }
    return reply(mode === 'ready' || mode === 'stale' ? completionReview() : mode === 'done' ? completedCompletionReview() : {}, mode === 'error' ? 503 : 200)
  })
  vi.stubGlobal('fetch', fetcher); vi.useFakeTimers(); render(<Harness />)
  await act(async () => { await Promise.resolve() })
  await open(); submit()
  await act(async () => { await Promise.resolve() })
  expect(screen.getByRole('heading', { name: 'Testing Completed' })).toBeVisible()
  mode = 'error'
  await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
  expect(screen.getByRole('heading', { name: 'Testing Completed' })).toBeVisible()
  mode = 'stale'
  await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
  expect(screen.getByRole('heading', { name: 'Testing Completed' })).toBeVisible()
  fireEvent.click(screen.getByRole('button', { name: 'Toggle completion' }))
  fireEvent.click(screen.getByRole('button', { name: 'Toggle completion' }))
  expect(screen.getByRole('heading', { name: 'Testing Completed' })).toBeVisible()
  expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1)
})

it('handles stale POST rejection by requiring a fresh explicit confirmation', async () => {
  const fetcher = vi.fn(async (_input: RequestInfo | URL, options?: RequestInit) => reply(options?.method === 'POST' ? {} : completionReview(), options?.method === 'POST' ? 409 : 200))
  vi.stubGlobal('fetch', fetcher); render(<Harness />)
  await open(); submit()
  expect(await screen.findByRole('alert')).toHaveTextContent('The assessment changed')
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
  expect(await screen.findByRole('heading', { name: 'Ready to complete' })).toBeVisible()
  expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1)
})

it('keeps uncertain completion locked across a remount and Testing readback until a receipt arrives', async () => {
  let done = false
  const fetcher = vi.fn(async (_input: RequestInfo | URL, options?: RequestInit) => {
    if (options?.method === 'POST') throw new Error('Lost response')
    return reply(done ? completedCompletionReview() : completionReview())
  })
  vi.stubGlobal('fetch', fetcher); render(<Harness />)
  await open(); submit()
  await screen.findByRole('heading', { name: 'Completion outcome unverified' })
  fireEvent.click(screen.getByRole('button', { name: 'Toggle completion' }))
  fireEvent.click(screen.getByRole('button', { name: 'Toggle completion' }))
  await screen.findByRole('heading', { name: 'Ready to complete' })
  expect(screen.getByRole('button', { name: 'Complete Testing' })).toBeDisabled()
  fireEvent.click(screen.getByRole('button', { name: 'Verify completion status' }))
  await act(async () => { await Promise.resolve() })
  expect(screen.getByRole('button', { name: 'Complete Testing' })).toBeDisabled()
  done = true
  fireEvent.click(screen.getByRole('button', { name: 'Verify completion status' }))
  expect(await screen.findByRole('heading', { name: 'Testing Completed' })).toBeVisible()
  expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1)
})

it('restores persisted completion on a fresh mount without POST or invented actor names', async () => {
  const { fetcher } = setup(completedCompletionReview())
  expect(await screen.findByRole('heading', { name: 'Testing Completed' })).toBeVisible()
  expect(screen.queryByText(/synthetic-completion-actor/)).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Complete Testing' })).not.toBeInTheDocument()
  expect(fetcher.mock.calls.every(([, options]) => !options?.method)).toBe(true)
})

it('rejects a late readiness response after assessment changes', async () => {
  let old: (value: ReturnType<typeof reply>) => void = () => { throw new Error('Old GET not started') }
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    if (String(input).includes(assessmentId)) return new Promise<ReturnType<typeof reply>>(resolve => { old = resolve })
    return reply({ ...completionReview(), assessment_id: 'next-assessment', assessment_name: 'Next assessment' })
  }))
  const view = render(<Harness key={assessmentId} />)
  view.rerender(<Harness key="next" id="next-assessment" />)
  await screen.findByRole('heading', { name: 'Ready to complete' })
  await act(async () => { old(reply(completedCompletionReview())) })
  expect(screen.queryByRole('heading', { name: 'Testing Completed' })).not.toBeInTheDocument()
})

it('keeps an in-flight POST uncertain after tab unmount and rejects its late response', async () => {
  let resolvePost: (value: ReturnType<typeof reply>) => void = () => { throw new Error('POST not started') }
  const fetcher = vi.fn(async (_input: RequestInfo | URL, options?: RequestInit) => {
    if (options?.method === 'POST') return new Promise<ReturnType<typeof reply>>(resolve => { resolvePost = resolve })
    return reply(completionReview())
  })
  vi.stubGlobal('fetch', fetcher); render(<Harness />)
  const dialog = await open(); submit()
  expect(within(dialog).getByRole('button', { name: 'Cancel' })).toBeDisabled()
  fireEvent(dialog, new Event('cancel', { bubbles: true, cancelable: true }))
  expect(screen.getByRole('dialog')).toBeVisible()
  fireEvent.click(screen.getByRole('button', { name: 'Toggle completion' }))
  fireEvent.click(screen.getByRole('button', { name: 'Toggle completion' }))
  await screen.findByRole('heading', { name: 'Ready to complete' })
  expect(screen.getByRole('heading', { name: 'Completion outcome unverified' })).toBeVisible()
  expect(screen.getByRole('button', { name: 'Complete Testing' })).toBeDisabled()
  await act(async () => { resolvePost(reply(completedCompletionReview())) })
  expect(screen.queryByRole('heading', { name: 'Testing Completed' })).not.toBeInTheDocument()
  expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1)
})

it('hides protected receipt data when access is lost instead of reusing it after remount', async () => {
  let denied = false
  vi.stubGlobal('fetch', vi.fn(async () => reply(denied ? {} : completedCompletionReview(), denied ? 403 : 200)))
  vi.useFakeTimers(); render(<Harness />)
  await act(async () => { await Promise.resolve() })
  expect(screen.getByRole('heading', { name: 'Testing Completed' })).toBeVisible()
  denied = true
  await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
  expect(screen.queryByRole('heading', { name: 'Testing Completed' })).not.toBeInTheDocument()
  expect(screen.getByRole('region', { name: 'Completed' })).toHaveTextContent('—')
  fireEvent.click(screen.getByRole('button', { name: 'Toggle completion' }))
  fireEvent.click(screen.getByRole('button', { name: 'Toggle completion' }))
  expect(screen.queryByRole('heading', { name: 'Testing Completed' })).not.toBeInTheDocument()
})


it.each([0, 1, 4])(
  'displays the verified candidate findings count: %s',
  async count => {
    const value = completionReview()
    value.summary.candidate_findings = count
    setup(value)

    await screen.findByRole('heading', {
      name: 'Ready to complete',
    })

    const message = count === 0
      ? 'No candidate findings were identified.'
      : `${count} candidate finding${count === 1 ? '' : 's'} identified for review in the Findings stage.`

    expect(screen.getByText(message)).toBeVisible()
  }
)


it('enables navigation after a verified completion receipt', async () => {
  const navigate = vi.fn()
  vi.stubGlobal('fetch', vi.fn(async () =>
    reply(completedCompletionReview())))

  render(<TestingCompletion
    assessmentId={assessmentId}
    csrfToken="synthetic-csrf"
    operation={{ phase: 'idle' }}
    onOperationChange={vi.fn()}
    onExpired={expired}
    onDecisionsChanged={decisionsChanged}
    onContinue={vi.fn()}
    onRecommendations={vi.fn()}
    onContinueToFindings={navigate}
  />)

  expect(await screen.findByRole('heading', {
    name: 'Testing Completed',
  })).toBeVisible()

  const button = screen.getByRole('button', {
    name: 'Continue to Findings',
  })
  expect(button).toBeEnabled()
  fireEvent.click(button)
  expect(navigate).toHaveBeenCalledTimes(1)
})

it('does not expose Findings navigation before completion', async () => {
  const navigate = vi.fn()
  vi.stubGlobal('fetch', vi.fn(async () => reply(completionReview())))

  render(<TestingCompletion
    assessmentId={assessmentId}
    csrfToken="synthetic-csrf"
    operation={{ phase: 'idle' }}
    onOperationChange={vi.fn()}
    onExpired={expired}
    onDecisionsChanged={decisionsChanged}
    onContinue={vi.fn()}
    onRecommendations={vi.fn()}
    onContinueToFindings={navigate}
  />)

  await screen.findByRole('heading', { name: 'Ready to complete' })
  expect(screen.queryByRole('button', {
    name: 'Continue to Findings',
  })).not.toBeInTheDocument()
  expect(navigate).not.toHaveBeenCalled()
})
