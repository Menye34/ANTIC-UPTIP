import { AssessmentStartError, startRequest } from './assessmentStart'

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
  authorization_id: string | null
  execution_kind?: 'recommended'
  created_at: string
  updated_at: string
  execution_authorized: false
}
export interface TestingData {
  assessment_id: string
  lifecycle_status: 'Draft' | 'Ready' | 'Testing' | 'Finding Review'
  can_schedule_service_discovery?: boolean
  counts: { total: number; queued: number; in_progress: number; completed: number; failed: number; stopped: number; blocked: number; cancelled: number }
  executions: Execution[]
  authorization_scope: {
    boundaries?: Array<{ value: string; kind: string }> | null
    scope_current?: boolean
    authorized_by?: { id: string; username: string; confirmed_at: string } | null
    authorization_id: string | null
    scope_revision: number | null
    scope_digest: string | null
    mode: 'full' | 'partial' | null
    policy: { id?: string; version?: number } | null
    excluded_activities: unknown[]
    excluded_targets: unknown[]
  }
  discovery_totals?: { open_ports: number | null; services: number | null; web_targets: number | null }
  discovered_so_far: Array<{ id: string; execution_id: string; target_id: string; type: string; data: Record<string, unknown>; partial: boolean }>
  recent_activity: Array<{ event: string; execution_id: string; occurred_at: string }>
}
export interface ExecutionDetails extends Execution {
  dispatch_status: string
  recommended_result?: { termination_verified: boolean; partial: boolean; integrity_verified: boolean; failure_reason: string | null }
  dispatch_history?: { id: string; event: string; reason_code: string; occurred_at: string; attempt_id: string | null } | null
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
  if ((result.can_schedule_service_discovery !== undefined && typeof result.can_schedule_service_discovery !== 'boolean')
      || result.assessment_id !== assessmentId || !['Draft', 'Ready', 'Testing', 'Finding Review'].includes(result.lifecycle_status)
      || !result.counts || !Number.isInteger(result.counts.total) || result.counts.total < 0
      || keys.some(key => !Number.isInteger(result.counts[key]) || result.counts[key] < 0)
      || keys.reduce((sum, key) => sum + result.counts[key], 0) !== result.counts.total
      || !Array.isArray(result.executions) || result.executions.length !== result.counts.total
      || !result.executions.every(validExecution) || new Set(result.executions.map(row => row.id)).size !== result.executions.length
      || !result.authorization_scope || !Array.isArray(result.discovered_so_far) || !Array.isArray(result.recent_activity)) {
    throw new Error('Invalid Testing response')
  }
  const totals = result.discovery_totals
  const scope = result.authorization_scope
  if ((totals !== undefined && (!totals || ['open_ports', 'services', 'web_targets'].some(key => {
    const value = totals[key as keyof typeof totals]
    return value !== null && (!Number.isInteger(value) || value < 0)
  }))) || (scope.boundaries != null && (!Array.isArray(scope.boundaries)
    || scope.boundaries.some(b => typeof b.value !== 'string' || typeof b.kind !== 'string')))
    || (scope.authorized_by != null && (typeof scope.authorized_by.id !== 'string'
      || typeof scope.authorized_by.username !== 'string' || !scope.authorized_by.username
      || !Number.isFinite(Date.parse(scope.authorized_by.confirmed_at))))) throw new Error('Invalid Testing context')
  const rowCounts = executionStates.map(status => result.executions.filter(row => row.status === status).length)
  if (rowCounts.some((count, i) => count !== result.counts[keys[i]])) throw new Error('Inconsistent Testing counts')
  return result
}

export async function getExecutionDetails(assessmentId: string, executionId: string, signal: AbortSignal) {
  const result = await startRequest<ExecutionDetails>(assessmentId, '/testing/executions/' + encodeURIComponent(executionId), signal)
  if (!validExecution(result) || result.id !== executionId || !Array.isArray(result.attempts)
      || !Array.isArray(result.evidence) || !Array.isArray(result.processing) || !Array.isArray(result.observations)
      || !Array.isArray(result.events)) throw new Error('Invalid execution details')
  const nullableText = (value: unknown) => value === null || typeof value === 'string'
  if ((result.execution_kind === 'recommended' && (!result.recommended_result
      || typeof result.recommended_result.termination_verified !== 'boolean'
      || typeof result.recommended_result.partial !== 'boolean'
      || typeof result.recommended_result.integrity_verified !== 'boolean'
      || !nullableText(result.recommended_result.failure_reason)))
    || typeof result.dispatch_status !== 'string'
    || (result.dispatch_history != null && (typeof result.dispatch_history.id !== 'string'
      || !['dispatch_blocked', 'execution_claimed', 'scanner_started'].includes(result.dispatch_history.event)
      || result.dispatch_history.event !== result.dispatch_status
      || typeof result.dispatch_history.reason_code !== 'string'
      || !Number.isFinite(Date.parse(result.dispatch_history.occurred_at))
      || !nullableText(result.dispatch_history.attempt_id)))
    || result.attempts.some(a => !a || typeof a.id !== 'string' || !Number.isInteger(a.attempt_number)
      || a.attempt_number < 1 || typeof a.status !== 'string' || !nullableText(a.reason_code)
      || !nullableText(a.started_at) || !nullableText(a.finished_at) || !nullableText(a.recovery_reason))
    || result.evidence.some(e => !e || typeof e.id !== 'string' || typeof e.format !== 'string'
      || !Number.isInteger(e.size_bytes) || e.size_bytes < 0 || e.size_bytes > 10 * 1024 * 1024
      || typeof e.partial !== 'boolean' || !/^[a-f0-9]{64}$/.test(e.sha256)
      || !Number.isFinite(Date.parse(e.collected_at)))
    || result.processing.some(p => !p || typeof p.id !== 'string' || typeof p.status !== 'string'
      || typeof p.processor !== 'string' || typeof p.version !== 'string'
      || !Number.isInteger(p.observation_count) || p.observation_count < 0 || typeof p.partial !== 'boolean')
    || result.observations.some(o => !o || typeof o.id !== 'string' || typeof o.type !== 'string'
      || !o.data || typeof o.data !== 'object' || Array.isArray(o.data)
      || typeof o.partial !== 'boolean' || typeof o.evidence_id !== 'string')
    || result.events.some(e => !e || typeof e.id !== 'string' || typeof e.event !== 'string'
      || typeof e.reason_code !== 'string' || !nullableText(e.attempt_id)
      || !Number.isFinite(Date.parse(e.occurred_at)))) throw new Error('Invalid execution details')
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
  kind: 'review_host_discovery' | 'evidence_followup'
  title: string
  target_id: string
  target: string
  service: string | null
  port: number | null
  reason: string
  source_observation_id: string
  source_evidence_id: string
  execution_available: false
  execution_status: 'not_supported' | 'pending_integration'
  suggested_test: string | null
  suggested_tool: string | null
  review_outcome?: 'Accepted' | 'Rejected' | null
  context_digest?: string
  explanation?: string[]
  tool_integration_status?: 'pending_integration'
  execution_unavailability_reason?: string
  proposed_test?: { id: string; version: number; name: string; tool: string; description: string; profile_id: null; definition_digest: string }
  source_test?: { test_name: string; tool: string; status: ExecutionStatus } | null
}
export interface RecommendationData {
  assessment_id: string
  count: number
  recommendations: Recommendation[]
  decision_counts: DecisionCounts
  execution_authorized: false
}

function validProposal(row: Recommendation): boolean {
  if (row.kind === 'review_host_discovery') return row.execution_status === 'not_supported'
    && row.suggested_test === null && row.suggested_tool === null && row.port === null && row.service === null
  const p = row.proposed_test
  return row.execution_status === 'pending_integration' && row.tool_integration_status === 'pending_integration'
    && row.execution_unavailability_reason === 'tool_integration_pending'
    && typeof row.context_digest === 'string' && row.context_digest === row.id
    && Array.isArray(row.explanation) && row.explanation.length === 3
    && row.explanation.every(text => typeof text === 'string' && text.length > 0)
    && [null, 'Accepted', 'Rejected'].includes(row.review_outcome ?? null)
    && typeof row.service === 'string' && Number.isInteger(row.port) && row.port! > 0 && row.port! <= 65535
    && !!p && ['Nikto', 'OWASP ZAP'].includes(p.tool) && p.name === row.suggested_test && p.tool === row.suggested_tool
    && typeof p.description === 'string' && p.profile_id === null && Number.isInteger(p.version) && p.version > 0
    && typeof p.id === 'string' && /^[a-f0-9]{64}$/.test(p.definition_digest)
}

export async function getRecommendations(assessmentId: string, signal: AbortSignal) {
  const result = await startRequest<RecommendationData>(assessmentId, '/testing/recommendations', signal)
  if (result.assessment_id !== assessmentId || result.execution_authorized !== false
    || !Number.isInteger(result.count) || result.count < 0
    || !Array.isArray(result.recommendations) || result.count !== result.recommendations.length
    || new Set(result.recommendations.map(row => row.id)).size !== result.count
    || result.recommendations.some(row => !row || typeof row.id !== 'string'
      || ![null, 'Reviewed', 'Deferred'].includes(row.decision)
      || !['review_host_discovery', 'evidence_followup'].includes(row.kind) || typeof row.title !== 'string'
      || typeof row.target_id !== 'string' || typeof row.target !== 'string'
      || typeof row.reason !== 'string' || typeof row.source_observation_id !== 'string'
      || typeof row.source_evidence_id !== 'string' || row.execution_available !== false
      || !validProposal(row)
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

export interface OriginalEvidence {
  assessment_id: string; execution_id: string; evidence_id: string
  sha256: string; size_bytes: number; format: string; partial: boolean; content: string
}
export async function getOriginalEvidence(assessmentId: string, executionId: string,
  source: ExecutionDetails['evidence'][number], signal: AbortSignal) {
  const value = await startRequest<OriginalEvidence>(assessmentId,
    '/testing/executions/' + encodeURIComponent(executionId) + '/evidence/' + encodeURIComponent(source.id), signal)
  if (value.assessment_id !== assessmentId || value.execution_id !== executionId || value.evidence_id !== source.id
    || typeof value.content !== 'string' || value.sha256 !== source.sha256 || !/^[a-f0-9]{64}$/.test(value.sha256)
    || value.size_bytes !== source.size_bytes || !Number.isInteger(value.size_bytes) || value.size_bytes < 0
    || value.size_bytes > 10 * 1024 * 1024 || new TextEncoder().encode(value.content).byteLength !== value.size_bytes
    || value.format !== source.format || value.partial !== source.partial) throw new Error('Invalid original evidence response')
  return value
}

export interface RecommendedReceipt {
  id: string; assessment_id: string; recommendation_id: string; status: ExecutionStatus;
  tool: string; already_requested: boolean; execution_authorized: false
}
function validRecommendedReceipt(value: RecommendedReceipt, assessmentId: string, recommendationId: string) {
  return value && typeof value.id === 'string' && value.assessment_id === assessmentId
    && value.recommendation_id === recommendationId && value.tool === 'Nikto'
    && executionStates.includes(value.status) && typeof value.already_requested === 'boolean'
    && value.execution_authorized === false
}
export async function getRecommendedReceipt(assessmentId: string, recommendationId: string, signal: AbortSignal) {
  const value = await startRequest<RecommendedReceipt>(assessmentId,
    '/testing/recommendations/' + encodeURIComponent(recommendationId) + '/start-receipt', signal)
  if (!validRecommendedReceipt(value, assessmentId, recommendationId)) throw new Error('Invalid recommended-test start receipt')
  return value
}
export class RecommendedStartUncertainError extends Error {
  constructor() { super('Test scheduling outcome remains unverified. Check saved status; do not submit again.') }
}
/** Only the reviewed digest is sent; target/port/argv are server-derived. */
export async function startRecommendedTest(assessmentId: string, recommendationId: string,
  csrfToken: string, signal: AbortSignal, snapshotDigest: string) {
  if (!/^[a-f0-9]{64}$/.test(snapshotDigest)) throw new Error('Invalid reviewed test digest')
  try {
    const value = await startRequest<RecommendedReceipt>(assessmentId,
      '/testing/recommendations/' + encodeURIComponent(recommendationId) + '/start', signal,
      { method: 'POST', headers: { 'X-CSRF-Token': csrfToken, 'Content-Type': 'application/json' },
        body: JSON.stringify({ snapshot_digest: snapshotDigest }) })
    if (!validRecommendedReceipt(value, assessmentId, recommendationId)) throw new Error('Invalid recommended-test start receipt')
    return value
  } catch (error) {
    if (signal.aborted) throw error
    if (error instanceof AssessmentStartError && error.status < 500 && ![408,429].includes(error.status)) throw error
    try { return await getRecommendedReceipt(assessmentId, recommendationId, signal) }
    catch { throw new RecommendedStartUncertainError() }
  }
}

export interface RecommendedReadiness {
  assessment_id: string; recommendation_id: string; ready: boolean; reason_code: string;
  snapshot_digest: string | null; configured_profile: string | null; endpoint: string | null
}
export async function getRecommendedStartReadiness(assessmentId: string, recommendationId: string, signal: AbortSignal) {
  const result = await startRequest<RecommendedReadiness>(assessmentId,
    '/testing/recommendations/' + encodeURIComponent(recommendationId) + '/start-readiness', signal)
  const nullableText = (value: unknown) => value === null || typeof value === 'string'
  if (result.assessment_id !== assessmentId || result.recommendation_id !== recommendationId
    || typeof result.ready !== 'boolean' || typeof result.reason_code !== 'string'
    || !nullableText(result.configured_profile) || !nullableText(result.endpoint)
    || !(result.snapshot_digest === null || typeof result.snapshot_digest === 'string' && /^[a-f0-9]{64}$/.test(result.snapshot_digest))
    || result.ready && (!result.snapshot_digest || !result.configured_profile || !result.endpoint)) {
    throw new Error('Invalid Start Test readiness response')
  }
  return result
}
