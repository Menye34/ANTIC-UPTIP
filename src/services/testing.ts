import { startRequest } from './assessmentStart'

export const executionStates = ['Queued', 'Running', 'Completed', 'Failed', 'Stopped', 'Blocked', 'Cancelled'] as const
export type ExecutionStatus = typeof executionStates[number]
export interface Execution {
  id: string
  target_id: string
  profile_id: string
  profile_version: number
  test_name: string
  tool: string
  target: string
  status: ExecutionStatus
  authorization_id: string
  created_at: string
  updated_at: string
  execution_authorized: false
}
export interface TestingData {
  assessment_id: string
  lifecycle_status: 'Draft' | 'Ready' | 'Testing' | 'Finding Review'
  counts: { total: number; queued: number; in_progress: number; completed: number; failed: number; stopped: number; blocked: number; cancelled: number }
  executions: Execution[]
  authorization_scope: {
    authorization_id: string | null
    scope_revision: number | null
    scope_digest: string | null
    mode: 'full' | 'partial' | null
    policy: { id?: string; version?: number } | null
    excluded_activities: unknown[]
    excluded_targets: unknown[]
  }
  discovered_so_far: Array<{ id: string; execution_id: string; target_id: string; type: string; data: Record<string, unknown>; partial: boolean }>
  recent_activity: Array<{ event: string; execution_id: string; occurred_at: string }>
}
export interface ExecutionDetails extends Execution {
  dispatch_status: string
  attempts: Array<{ id: string; attempt_number: number; status: string; reason_code: string | null; started_at: string | null; finished_at: string | null; exit_code: number | null; recovery_reason: string | null }>
  evidence: Array<{ id: string; format: string; size_bytes: number; partial: boolean; collected_at: string; sha256: string }>
  processing: Array<{ id: string; status: string; processor: string; version: string; error_code: string | null; observation_count: number; partial: boolean }>
  observations: Array<{ id: string; type: string; data: Record<string, unknown>; partial: boolean; evidence_id: string }>
  events: Array<{ id: string; event: string; reason_code: string; occurred_at: string; attempt_id: string | null }>
}

function validExecution(value: Execution) {
  return value && typeof value.id === 'string' && typeof value.target_id === 'string'
    && typeof value.test_name === 'string' && typeof value.tool === 'string' && typeof value.target === 'string'
    && typeof value.profile_id === 'string' && Number.isInteger(value.profile_version) && value.profile_version > 0
    && executionStates.includes(value.status) && value.execution_authorized === false
}

export async function getTesting(assessmentId: string, signal: AbortSignal) {
  const result = await startRequest<TestingData>(assessmentId, '/testing', signal)
  const keys = ['queued', 'in_progress', 'completed', 'failed', 'stopped', 'blocked', 'cancelled'] as const
  if (result.assessment_id !== assessmentId || !['Draft', 'Ready', 'Testing', 'Finding Review'].includes(result.lifecycle_status)
      || !result.counts || !Number.isInteger(result.counts.total) || result.counts.total < 0
      || keys.some(key => !Number.isInteger(result.counts[key]) || result.counts[key] < 0)
      || keys.reduce((sum, key) => sum + result.counts[key], 0) !== result.counts.total
      || !Array.isArray(result.executions) || result.executions.length !== result.counts.total
      || !result.executions.every(validExecution) || new Set(result.executions.map(row => row.id)).size !== result.executions.length
      || !result.authorization_scope || !Array.isArray(result.discovered_so_far) || !Array.isArray(result.recent_activity)) {
    throw new Error('Invalid Testing response')
  }
  const rowCounts = executionStates.map(status => result.executions.filter(row => row.status === status).length)
  if (rowCounts.some((count, i) => count !== result.counts[keys[i]])) throw new Error('Inconsistent Testing counts')
  return result
}

export async function getExecutionDetails(assessmentId: string, executionId: string, signal: AbortSignal) {
  const result = await startRequest<ExecutionDetails>(assessmentId, '/testing/executions/' + encodeURIComponent(executionId), signal)
  if (!validExecution(result) || result.id !== executionId || !Array.isArray(result.attempts)
      || !Array.isArray(result.evidence) || !Array.isArray(result.processing) || !Array.isArray(result.observations)
      || !Array.isArray(result.events)) throw new Error('Invalid execution details')
  return result
}

export type RecommendationDecision = 'Reviewed' | 'Deferred' | null
export interface DecisionCounts {
  total: number
  pending_review: number
  reviewed: number
  deferred: number
  pending_completion: number
}

export interface Recommendation {
  decision: RecommendationDecision
  id: string
  kind: 'review_host_discovery'
  title: string
  target_id: string
  target: string
  service: string | null
  port: number | null
  reason: string
  source_observation_id: string
  source_evidence_id: string
  execution_available: false
  execution_status: 'not_supported'
  suggested_test: null
  suggested_tool: null
  source_test?: { test_name: string; tool: string; status: ExecutionStatus } | null
}
export interface RecommendationData {
  assessment_id: string
  count: number
  recommendations: Recommendation[]
  decision_counts: DecisionCounts
  execution_authorized: false
}
export async function getRecommendations(assessmentId: string, signal: AbortSignal) {
  const result = await startRequest<RecommendationData>(assessmentId, '/testing/recommendations', signal)
  if (result.assessment_id !== assessmentId || result.execution_authorized !== false
    || !Number.isInteger(result.count) || result.count < 0
    || !Array.isArray(result.recommendations) || result.count !== result.recommendations.length
    || new Set(result.recommendations.map(row => row.id)).size !== result.count
    || result.recommendations.some(row => !row || typeof row.id !== 'string'
      || ![null, 'Reviewed', 'Deferred'].includes(row.decision)
      || row.kind !== 'review_host_discovery' || row.title !== 'Review responding host'
      || typeof row.target_id !== 'string' || typeof row.target !== 'string'
      || typeof row.reason !== 'string' || typeof row.source_observation_id !== 'string'
      || typeof row.source_evidence_id !== 'string' || row.execution_available !== false
      || row.execution_status !== 'not_supported' || row.suggested_test !== null
      || row.suggested_tool !== null || row.port !== null || row.service !== null
      || (row.source_test != null && (typeof row.source_test.test_name !== 'string'
        || typeof row.source_test.tool !== 'string' || !executionStates.includes(row.source_test.status))))) {
    throw new Error('Invalid recommendations response')
  }
  const counts = result.decision_counts
  if (!counts || [counts.total, counts.pending_review, counts.reviewed, counts.deferred, counts.pending_completion]
    .some(value => !Number.isInteger(value) || value < 0)
    || counts.total !== result.count
    || counts.pending_review !== result.recommendations.filter(row => row.decision === null).length
    || counts.reviewed !== result.recommendations.filter(row => row.decision === 'Reviewed').length
    || counts.deferred !== result.recommendations.filter(row => row.decision === 'Deferred').length
    || counts.pending_completion !== counts.pending_review + counts.deferred) {
    throw new Error('Invalid recommendation decision counts')
  }
  return result
}

export interface RecommendationCheck {
  assessment_id: string
  recommendation_id: string
  eligible: false
  execution_available: false
  authorization_available: false
  available_profiles: []
  reason_code: string
}
export async function getRecommendationCheck(assessmentId: string, recommendationId: string,
  kind: 'eligibility' | 'authorization-review', signal: AbortSignal) {
  const result = await startRequest<RecommendationCheck>(assessmentId,
    '/testing/recommendations/' + encodeURIComponent(recommendationId) + '/' + kind, signal)
  if (result.assessment_id !== assessmentId || result.recommendation_id !== recommendationId
      || result.eligible !== false || result.execution_available !== false || result.authorization_available !== false
      || !Array.isArray(result.available_profiles) || result.available_profiles.length !== 0
      || typeof result.reason_code !== 'string') throw new Error('Invalid recommendation review')
  return result
}
