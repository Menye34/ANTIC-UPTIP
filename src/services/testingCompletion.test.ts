import { afterEach, expect, it, vi } from 'vitest'
import { AssessmentStartError } from './assessmentStart'
import { completeTesting, CompletionOutcomeUncertainError, getCompletionReview, validateCompletionReview } from './testingCompletion'
import type { CompletionReview } from './testingCompletion'

const id = '91689bd1-d5e3-40c6-9938-60143e98e1e9'
const actor = '5cd32dc2-cdf6-4dd8-8506-807825a10952'
const hash = 'a'.repeat(64)
const rec = 'b'.repeat(64)
const response = (body: unknown, status = 200) => ({ ok: status < 400, status, json: async () => body })
afterEach(() => { vi.unstubAllGlobals() })

function review(): CompletionReview {
  return {
    assessment_id: id, assessment_name: 'Synthetic completion contract', lifecycle_status: 'Testing',
    ready: true, can_complete: true, snapshot_schema_version: 2, snapshot_digest: hash,
    summary: { total: 1, counts: { Queued: 0, Running: 0, Completed: 1, Failed: 0, Stopped: 0, Blocked: 0, Cancelled: 0 },
      active_attempts: 0, active_execution_requests: 0, recovery_required_requests: 0,
      processing_errors: 0, processing_pending: 0, missing_processing: 0,
      recommendation_count: 1, pending_recommendation_ids: [], reviewed_recommendations: 1, deferred_recommendations: 0,
      decision_counts: { total: 1, pending_review: 0, reviewed: 1, deferred: 0, pending_completion: 0 },
      candidate_findings: null, blockers: [] },
    blocker_details: [], recommendations: [{ id: rec, title: 'Review responding host', decision: 'Reviewed' }], completion: null,
  }
}

function completed(legacy = false): CompletionReview {
  const value = review()
  const snapshot = structuredClone(value.summary)
  const stored = legacy ? { original_legacy_receipt: true } : { ...snapshot, _completion_contract: {
    schema_version: 2, snapshot_digest: hash,
    inputs: { schema_version: 2, assessment_id: id, creator_id: actor, lifecycle_status: 'Testing', scope_revision: 1,
      executions: [{ id: 'synthetic-request' }], attempts: [], processing: [], observations: [], decisions: [] },
  } }
  return { ...value, lifecycle_status: 'Finding Review', ready: false, can_complete: false,
    snapshot_digest: 'c'.repeat(64), completion: {
      completed_at: '2026-11-19T10:00:00.123456+01:00', actor_id: actor, snapshot: stored,
      snapshot_schema_version: legacy ? 1 : 2, snapshot_digest: legacy ? null : hash,
    } }
}

it('validates ready, actor-ineligible, Draft and missing-receipt GET states', () => {
  expect(validateCompletionReview(review(), id).ready).toBe(true)
  expect(validateCompletionReview({ ...review(), can_complete: false }, id).can_complete).toBe(false)
  const draft = review()
  draft.lifecycle_status = 'Draft'; draft.ready = false; draft.can_complete = false
  draft.summary.blockers = ['incorrect_lifecycle']
  draft.blocker_details = [{ code: 'incorrect_lifecycle', message: 'Not Testing.', count: null, action: null }]
  expect(validateCompletionReview(draft, id).ready).toBe(false)
  const missing = completed()
  missing.completion = null
  missing.summary.blockers = ['missing_completion_receipt']
  missing.blocker_details = [{ code: 'missing_completion_receipt', message: 'Receipt unavailable.', count: null, action: null }]
  expect(validateCompletionReview(missing, id).completion).toBeNull()
})

it.each([false, true])('validates current and legacy receipts without rewriting their snapshots: legacy=%s', legacy => {
  const value = completed(legacy)
  const before = JSON.stringify(value)
  expect(validateCompletionReview(value, id)).toBe(value)
  expect(JSON.stringify(value)).toBe(before)
  if (legacy) expect(value.completion!.snapshot).toEqual({ original_legacy_receipt: true })
})

const defects: Array<[string, (v: CompletionReview) => unknown]> = [
  ['assessment identity', v => ({ ...v, assessment_id: 'another-assessment' })],
  ['unknown lifecycle', v => ({ ...v, lifecycle_status: 'Completed' })],
  ['missing capability', v => { Reflect.deleteProperty(v, 'can_complete'); return v }],
  ['nonboolean ready', v => ({ ...v, ready: 'true' })],
  ['schema version', v => ({ ...v, snapshot_schema_version: 1 })],
  ['invalid digest', v => ({ ...v, snapshot_digest: 'invalid' })],
  ['negative count', v => { v.summary.active_attempts = -1; return v }],
  ['fractional count', v => { v.summary.processing_errors = .5; return v }],
  ['unsafe integer', v => { v.summary.total = Number.MAX_SAFE_INTEGER + 1; return v }],
  ['request total', v => { v.summary.total = 2; return v }],
  ['active request double count', v => { v.summary.active_execution_requests = 2; return v }],
  ['missing attempt-to-request binding', v => { v.summary.active_attempts = 1; return v }],
  ['decision counters', v => { v.summary.decision_counts.reviewed = 0; return v }],
  ['unknown decision', v => { Reflect.set(v.recommendations[0], 'decision', 'Approved'); return v }],
  ['missing decision', v => { Reflect.deleteProperty(v.recommendations[0], 'decision'); return v }],
  ['duplicated recommendation', v => { v.recommendations.push(v.recommendations[0]); return v }],
  ['pending IDs', v => { v.summary.pending_recommendation_ids = [rec]; return v }],
  ['missing blocker details', v => { Reflect.deleteProperty(v, 'blocker_details'); return v }],
  ['unexpected blocker code', v => { Reflect.set(v.summary, 'blockers', ['invented']); return v }],
  ['factual readiness mismatch', v => ({ ...v, ready: false })],
  ['receipt in Testing', v => ({ ...v, completion: completed().completion })],
  ['Finding Review without receipt or blocker', v => ({ ...v, lifecycle_status: 'Finding Review', ready: false, can_complete: false })],
]
it.each(defects)('rejects invalid GET contract: %s', async (_name, alter) => {
  vi.stubGlobal('fetch', vi.fn(async () => response(alter(review()))))
  await expect(getCompletionReview(id, new AbortController().signal)).rejects.toThrow('Invalid Testing Completion response')
})

it.each(['timestamp', 'actor', 'version', 'digest', 'assessment', 'lifecycle', 'creator', 'legacy provenance', 'safety gate'])('rejects invalid receipt %s', defect => {
  const value = completed()
  const receipt = value.completion!
  const meta = receipt.snapshot._completion_contract as { schema_version: number; snapshot_digest: string; inputs: Record<string, unknown> }
  if (defect === 'timestamp') receipt.completed_at = '2026-02-30T10:00:00Z'
  if (defect === 'actor') receipt.actor_id = ''
  if (defect === 'version') Reflect.set(receipt, 'snapshot_schema_version', 3)
  if (defect === 'digest') meta.snapshot_digest = 'd'.repeat(64)
  if (defect === 'assessment') meta.inputs.assessment_id = 'different'
  if (defect === 'lifecycle') meta.inputs.lifecycle_status = 'Finding Review'
  if (defect === 'creator') meta.inputs.creator_id = 'different'
  if (defect === 'legacy provenance') { receipt.snapshot_schema_version = 1; receipt.snapshot_digest = null }
  if (defect === 'safety gate') receipt.snapshot.processing_errors = 1
  expect(() => validateCompletionReview(value, id)).toThrow('Invalid Testing Completion response')
})

it.each(['Deferred', null] as const)('keeps %s recommendations completion-blocking', decision => {
  const value = review()
  value.ready = false
  value.recommendations[0].decision = decision
  value.summary.reviewed_recommendations = 0
  value.summary.deferred_recommendations = decision === 'Deferred' ? 1 : 0
  value.summary.pending_recommendation_ids = [rec]
  value.summary.decision_counts = { total: 1, pending_review: decision === null ? 1 : 0, reviewed: 0,
    deferred: decision === 'Deferred' ? 1 : 0, pending_completion: 1 }
  value.summary.blockers = ['pending_recommendations']
  value.blocker_details = [{ code: 'pending_recommendations', message: 'Review required.', count: 1, action: 'review_recommendations' }]
  expect(validateCompletionReview(value, id).ready).toBe(false)
  value.ready = true; value.summary.blockers = []; value.blocker_details = []
  expect(() => validateCompletionReview(value, id)).toThrow()
})

it('returns a validated successful POST receipt without unnecessary readback', async () => {
  const value = completed()
  const fetcher = vi.fn(async () => response(value))
  vi.stubGlobal('fetch', fetcher)
  expect(await completeTesting(id, hash, 'synthetic-csrf', new AbortController().signal)).toBe(value)
  expect(fetcher).toHaveBeenCalledTimes(1)
  expect(fetcher.mock.calls[0]).toBeDefined()
})

it.each(['lost', 'malformed', 'nonterminal', 'server error', 'invalid JSON'] as const)('recovers %s POST using one authenticated GET', async failure => {
  const fetcher = vi.fn(async (_input: RequestInfo | URL, options?: RequestInit) => {
    if (options?.method === 'POST') {
      if (failure === 'lost') throw new TypeError('Lost response')
      if (failure === 'malformed') return response({ lifecycle_status: 'Finding Review' })
      if (failure === 'nonterminal') return response(review())
      if (failure === 'server error') return response({}, 503)
      return { ok: true, status: 200, json: async () => { throw new SyntaxError('Invalid JSON') } }
    }
    return response(completed())
  })
  vi.stubGlobal('fetch', fetcher)
  const result = await completeTesting(id, hash, 'synthetic-csrf', new AbortController().signal)
  expect(result.lifecycle_status).toBe('Finding Review')
  expect(result.completion).not.toBeNull()
  expect(fetcher).toHaveBeenCalledTimes(2)
  const post = fetcher.mock.calls[0][1]!
  expect(post.method).toBe('POST')
  expect(post.headers).toMatchObject({ 'X-CSRF-Token': 'synthetic-csrf' })
  expect(JSON.parse(post.body as string)).toEqual({ snapshot_digest: hash, confirmed: true })
  expect(fetcher.mock.calls[1][1]).toMatchObject({ credentials: 'same-origin', cache: 'no-store' })
  expect(fetcher.mock.calls[1][1]?.method).toBeUndefined()
})

it.each(['Testing', 'missing receipt', 'malformed receipt', 'unreachable', 'unauthenticated', 'unavailable assessment'])('preserves uncertainty on %s readback without another POST', async outcome => {
  const fetcher = vi.fn(async (_input: RequestInfo | URL, options?: RequestInit) => {
    if (options?.method === 'POST') throw new Error('Uncertain POST')
    if (outcome === 'Testing') return response(review())
    if (outcome === 'missing receipt') return response({ ...completed(), completion: null })
    if (outcome === 'malformed receipt') return response({ ...completed(), completion: {} })
    if (outcome === 'unauthenticated') return response({}, 401)
    if (outcome === 'unavailable assessment') return response({}, 404)
    throw new Error('GET unavailable')
  })
  vi.stubGlobal('fetch', fetcher)
  await expect(completeTesting(id, hash, 'synthetic-csrf', new AbortController().signal)).rejects.toBeInstanceOf(CompletionOutcomeUncertainError)
  expect(fetcher).toHaveBeenCalledTimes(2)
  expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1)
})

it.each([401, 403, 404, 409, 422])('preserves definitive HTTP %s rejection without retry or readback', async status => {
  const fetcher = vi.fn(async () => response({}, status))
  vi.stubGlobal('fetch', fetcher)
  await expect(completeTesting(id, hash, 'synthetic-csrf', new AbortController().signal)).rejects.toMatchObject({ status })
  expect(fetcher).toHaveBeenCalledTimes(1)
})

it('does not continue network work after caller cancellation', async () => {
  const controller = new AbortController()
  const fetcher = vi.fn(async () => { controller.abort(); throw new DOMException('Cancelled', 'AbortError') })
  vi.stubGlobal('fetch', fetcher)
  await expect(completeTesting(id, hash, 'synthetic-csrf', controller.signal)).rejects.toBeInstanceOf(CompletionOutcomeUncertainError)
  expect(fetcher).toHaveBeenCalledTimes(1)
})

it('recognizes a persisted legacy receipt during recovery', async () => {
  const fetcher = vi.fn(async (_input: RequestInfo | URL, options?: RequestInit) => {
    if (options?.method === 'POST') throw new AssessmentStartError(503)
    return response(completed(true))
  })
  vi.stubGlobal('fetch', fetcher)
  const result = await completeTesting(id, hash, 'synthetic-csrf', new AbortController().signal)
  expect(result.completion!.snapshot_digest).toBeNull()
  expect(result.completion!.snapshot).toEqual({ original_legacy_receipt: true })
})
