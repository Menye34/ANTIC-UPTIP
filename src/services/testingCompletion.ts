import { startRequest } from './assessmentStart'

export interface CompletionReview {
  assessment_id: string
  lifecycle_status: 'Testing' | 'Finding Review'
  ready: boolean
  snapshot_digest: string
  summary: {
    total: number
    counts: Record<'Queued' | 'Running' | 'Completed' | 'Failed' | 'Stopped' | 'Blocked' | 'Cancelled', number>
    active_attempts: number
    processing_errors: number
    processing_pending: number
    missing_processing: number
    recommendation_count: number
    pending_recommendation_ids: string[]
    reviewed_recommendations: number
    candidate_findings: number | null
    blockers: string[]
  }
  recommendations: Array<{ id: string; title: string; decision: 'Reviewed' | 'Deferred' | null }>
  completion: null | { completed_at: string; actor_id: string; snapshot: CompletionReview['summary'] }
}

export async function getCompletionReview(assessmentId: string, signal: AbortSignal) {
  const result = await startRequest<CompletionReview>(assessmentId, '/testing/completion', signal)
  if (result.assessment_id !== assessmentId ||
      !['Testing', 'Finding Review'].includes(result.lifecycle_status) ||
      typeof result.ready !== 'boolean' || !/^[0-9a-f]{64}$/.test(result.snapshot_digest) ||
      !result.summary || !Array.isArray(result.summary.blockers) ||
      !Array.isArray(result.summary.pending_recommendation_ids) ||
      !Array.isArray(result.recommendations) ||
      (result.ready && (result.summary.blockers.length !== 0 || result.lifecycle_status !== 'Testing'))) {
    throw new Error('Invalid Testing Completion response')
  }
  return result
}

export async function decideRecommendation(
  assessmentId: string, recommendationId: string, decision: 'Reviewed' | 'Deferred',
  csrfToken: string, signal: AbortSignal,
) {
  return startRequest(assessmentId, '/testing/completion/decisions', signal, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
    body: JSON.stringify({ recommendation_id: recommendationId, decision }),
  })
}

export async function completeTesting(
  assessmentId: string, snapshotDigest: string, csrfToken: string, signal: AbortSignal,
) {
  return startRequest<CompletionReview>(assessmentId, '/testing/completion', signal, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
    body: JSON.stringify({ snapshot_digest: snapshotDigest, confirmed: true }),
  })
}
