import { AssessmentStartError, startRequest } from './assessmentStart'
import type { DecisionCounts, RecommendationDecision } from './testing'
import { executionStates } from './testing'

const blockerCodes = ['no_tests', 'missing_completion_receipt', 'active_tests', 'unsuccessful_tests',
  'processing_not_clear', 'pending_recommendations', 'incorrect_lifecycle'] as const
type BlockerCode = typeof blockerCodes[number]
export interface CompletionSummary {
  total: number
  counts: Record<typeof executionStates[number], number>
  active_attempts: number
  active_execution_requests: number
  recovery_required_requests: number
  processing_errors: number
  processing_pending: number
  missing_processing: number
  recommendation_count: number
  pending_recommendation_ids: string[]
  reviewed_recommendations: number
  deferred_recommendations: number
  decision_counts: DecisionCounts
  candidate_findings: null
  blockers: BlockerCode[]
}
export interface CompletionReview {
  assessment_id: string
  assessment_name: string
  lifecycle_status: 'Draft' | 'Ready' | 'Testing' | 'Finding Review'
  ready: boolean
  can_complete: boolean
  snapshot_schema_version: 2
  snapshot_digest: string
  summary: CompletionSummary
  blocker_details: Array<{ code: BlockerCode; message: string; count: number | null;
    action: 'view_tests' | 'review_recommendations' | null }>
  recommendations: Array<{ id: string; title: string; decision: RecommendationDecision }>
  completion: null | { completed_at: string; actor_id: string; snapshot: Record<string, unknown>;
    snapshot_schema_version: 1 | 2; snapshot_digest: string | null }
}

type ObjectValue = Record<string, unknown>
const object = (value: unknown): value is ObjectValue => value !== null && typeof value === 'object' && !Array.isArray(value)
const count = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) >= 0
const text = (value: unknown): value is string => typeof value === 'string' && value.trim().length > 0
const digest = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value)
const same = (a: unknown[], b: unknown[]) => a.length === b.length && a.every((value, i) => value === b[i])

function validSummary(value: unknown): value is CompletionSummary {
  if (!object(value) || !object(value.counts) || !object(value.decision_counts)) return false
  const s = value
  const c = value.counts
  const d = value.decision_counts
  if (['total', 'active_attempts', 'active_execution_requests', 'recovery_required_requests',
    'processing_errors', 'processing_pending', 'missing_processing', 'recommendation_count',
    'reviewed_recommendations', 'deferred_recommendations'].some(key => !count(s[key]))
    || executionStates.some(key => !count(c[key]))
    || ['total', 'pending_review', 'reviewed', 'deferred', 'pending_completion'].some(key => !count(d[key]))
    || !Array.isArray(s.pending_recommendation_ids) || !s.pending_recommendation_ids.every(digest)
    || new Set(s.pending_recommendation_ids).size !== s.pending_recommendation_ids.length
    || !Array.isArray(s.blockers) || !s.blockers.every(code => blockerCodes.includes(code))
    || new Set(s.blockers).size !== s.blockers.length || s.candidate_findings !== null) return false
  return executionStates.reduce((sum, key) => sum + (c[key] as number), 0) === s.total
    && (s.active_execution_requests as number) <= (s.total as number)
    && (s.active_execution_requests as number) >= (c.Queued as number) + (c.Running as number)
    && (!(s.active_attempts as number) || (s.active_execution_requests as number) > 0)
    && (s.active_attempts as number) >= (s.recovery_required_requests as number)
    && (s.recovery_required_requests as number) <= (s.active_execution_requests as number)
    && d.total === s.recommendation_count && d.reviewed === s.reviewed_recommendations
    && d.deferred === s.deferred_recommendations
    && d.total === (d.pending_review as number) + (d.reviewed as number) + (d.deferred as number)
    && d.pending_completion === (d.pending_review as number) + (d.deferred as number)
    && d.pending_completion === s.pending_recommendation_ids.length
}

function expectedBlockers(s: CompletionSummary, lifecycle: CompletionReview['lifecycle_status'], missingReceipt = false): BlockerCode[] {
  const result: BlockerCode[] = []
  if (s.total === 0) result.push('no_tests')
  if (missingReceipt) result.push('missing_completion_receipt')
  if (s.active_execution_requests || s.active_attempts) result.push('active_tests')
  if (s.counts.Failed + s.counts.Stopped + s.counts.Blocked + s.counts.Cancelled) result.push('unsuccessful_tests')
  if (s.processing_errors + s.processing_pending + s.missing_processing) result.push('processing_not_clear')
  if (s.pending_recommendation_ids.length) result.push('pending_recommendations')
  if (!['Testing', 'Finding Review'].includes(lifecycle)) result.push('incorrect_lifecycle')
  return result
}

function awareTimestamp(value: unknown): value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|[+-]\d\d:\d\d)$/.test(value)) return false
  const day = value.slice(0, 10)
  return Number.isFinite(Date.parse(value)) && new Date(day).toISOString().slice(0, 10) === day
}

function validReceipt(value: unknown, assessmentId: string): boolean {
  if (!object(value) || !awareTimestamp(value.completed_at) || !text(value.actor_id) || !object(value.snapshot)) return false
  const meta = value.snapshot._completion_contract
  if (value.snapshot_schema_version === 1) {
    // Preserve opaque historical JSON; never manufacture provenance for it.
    return (meta === undefined || meta === null) && value.snapshot_digest === null
  }
  if (value.snapshot_schema_version !== 2 || !digest(value.snapshot_digest) || !object(meta)
    || meta.schema_version !== 2 || meta.snapshot_digest !== value.snapshot_digest || !object(meta.inputs)) return false
  const inputs = meta.inputs
  const historical = Object.fromEntries(Object.entries(value.snapshot).filter(([key]) => key !== '_completion_contract'))
  return validSummary(historical) && historical.blockers.length === 0 && historical.total > 0
    && expectedBlockers(historical, 'Testing').length === 0
    && inputs.schema_version === 2 && inputs.assessment_id === assessmentId
    && inputs.lifecycle_status === 'Testing' && inputs.creator_id === value.actor_id
    && count(inputs.scope_revision)
    && ['executions', 'attempts', 'processing', 'observations', 'decisions'].every(key => Array.isArray(inputs[key]))
}

/** Validate transport facts; the backend remains the authorization and digest authority. */
export function validateCompletionReview(value: unknown, assessmentId: string): CompletionReview {
  const invalid = () => { throw new Error('Invalid Testing Completion response') }
  if (!object(value) || value.assessment_id !== assessmentId || !text(value.assessment_name)
    || !['Draft', 'Ready', 'Testing', 'Finding Review'].includes(value.lifecycle_status as string)
    || typeof value.ready !== 'boolean' || typeof value.can_complete !== 'boolean'
    || value.snapshot_schema_version !== 2 || !digest(value.snapshot_digest) || !validSummary(value.summary)
    || !Array.isArray(value.recommendations) || !Array.isArray(value.blocker_details)) return invalid()
  const s = value.summary
  const recs = value.recommendations
  if (recs.some(item => !object(item) || !digest(item.id) || !text(item.title)
    || ![null, 'Reviewed', 'Deferred'].includes(item.decision as RecommendationDecision))
    || new Set(recs.map(item => item.id)).size !== recs.length || recs.length !== s.recommendation_count
    || recs.filter(item => item.decision === 'Reviewed').length !== s.reviewed_recommendations
    || recs.filter(item => item.decision === 'Deferred').length !== s.deferred_recommendations
    || !same(recs.filter(item => item.decision !== 'Reviewed').map(item => item.id), s.pending_recommendation_ids)
    || value.blocker_details.some(item => !object(item) || !text(item.message)
      || (item.count !== null && !count(item.count))
      || ![null, 'view_tests', 'review_recommendations'].includes(item.action as string | null))
    || !same(value.blocker_details.map(item => item.code), s.blockers)
    || value.ready !== (value.lifecycle_status === 'Testing' && s.blockers.length === 0)
    || (value.can_complete && value.lifecycle_status !== 'Testing')) return invalid()
  if (!same(expectedBlockers(s, value.lifecycle_status as CompletionReview['lifecycle_status'],
    value.lifecycle_status === 'Finding Review' && value.completion === null), s.blockers)) return invalid()
  if (value.completion === null) {
    if (value.lifecycle_status === 'Finding Review' && !s.blockers.includes('missing_completion_receipt')) return invalid()
  } else if (value.lifecycle_status !== 'Finding Review' || !validReceipt(value.completion, assessmentId)) return invalid()
  return value as unknown as CompletionReview
}

export async function getCompletionReview(assessmentId: string, signal: AbortSignal) {
  return validateCompletionReview(await startRequest<unknown>(assessmentId, '/testing/completion', signal), assessmentId)
}

export async function decideRecommendation(
  assessmentId: string, recommendationId: string, decision: 'Reviewed' | 'Deferred',
  csrfToken: string, signal: AbortSignal, reviewOutcome?: 'Accepted' | 'Rejected',
) {
  return startRequest(assessmentId, '/testing/completion/decisions', signal, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
    body: JSON.stringify({ recommendation_id: recommendationId, decision, ...(reviewOutcome ? { review_outcome: reviewOutcome } : {}) }),
  })
}

export class CompletionOutcomeUncertainError extends Error {
  constructor() { super('Completion outcome is unverified. Read persisted state before another attempt.') }
}

function confirmed(result: CompletionReview): boolean {
  return result.lifecycle_status === 'Finding Review' && result.completion !== null
}

export async function completeTesting(
  assessmentId: string, snapshotDigest: string, csrfToken: string, signal: AbortSignal,
) {
  try {
    const result = validateCompletionReview(await startRequest<unknown>(assessmentId, '/testing/completion', signal, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
      body: JSON.stringify({ snapshot_digest: snapshotDigest, confirmed: true }),
    }), assessmentId)
    if (!confirmed(result)) throw new Error('Completion receipt unavailable')
    return result
  } catch (failure) {
    // Definitive request rejection preserves existing authorization/conflict handling.
    if (failure instanceof AssessmentStartError && failure.status >= 400 && failure.status < 500
      && ![408, 429].includes(failure.status)) throw failure
    if (!signal.aborted) {
      try {
        const current = await getCompletionReview(assessmentId, signal)
        if (confirmed(current)) return current
      } catch { /* Missing, invalid or inaccessible readback cannot establish success. */ }
    }
    // Even Testing readback can race a still-committing POST. Never retry automatically.
    throw new CompletionOutcomeUncertainError()
  }
}
