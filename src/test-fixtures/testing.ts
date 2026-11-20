import type { CompletionReview } from '../services/testingCompletion'
import type { ExecutionDetails, ExecutionStatus, TestingData } from '../services/testing'

// Synthetic API fixtures only; never imported by the application.
export const assessmentId = 'synthetic-assessment'
export function testingData(statuses: ExecutionStatus[] = []): TestingData {
  const keys = { Queued: 'queued', Running: 'in_progress', Completed: 'completed', Failed: 'failed',
    Stopped: 'stopped', Blocked: 'blocked', Cancelled: 'cancelled' } as const
  const counts = { total: statuses.length, queued: 0, in_progress: 0, completed: 0, failed: 0, stopped: 0, blocked: 0, cancelled: 0 }
  statuses.forEach(status => counts[keys[status]]++)
  return { assessment_id: assessmentId, lifecycle_status: statuses.length ? 'Testing' : 'Draft', counts,
    executions: statuses.map((status, i) => ({ id: 'synthetic-execution-' + i, target_id: 'synthetic-target-' + i,
      profile_id: 'network-discovery', profile_version: 2, test_name: 'Network Discovery', tool: 'Nmap',
      target: '192.0.2.' + (i + 1), status, authorization_id: 'synthetic-authorization',
      created_at: '2026-11-16T10:00:00Z', updated_at: '2026-11-16T10:00:00Z', execution_authorized: false })),
    authorization_scope: { authorization_id: statuses.length ? 'synthetic-authorization' : null,
      scope_revision: statuses.length ? 1 : null, scope_digest: null, mode: statuses.length ? 'full' : null,
      policy: statuses.length ? { id: 'uptip-baseline-scheduling', version: 2 } : null, excluded_activities: [], excluded_targets: [] },
    discovered_so_far: [], recent_activity: statuses.map((_, i) => ({ event: 'execution_queued',
      execution_id: 'synthetic-execution-' + i, occurred_at: '2026-11-16T10:00:00Z' })) }
}
export function executionDetails(): ExecutionDetails {
  return { ...testingData(['Queued']).executions[0], dispatch_status: 'requires_fresh_authorization',
    attempts: [], evidence: [], processing: [], observations: [], events: [] }
}

export function recommendationData(decision: 'Reviewed' | 'Deferred' | null = null) {
  return { assessment_id: assessmentId, count: 1, execution_authorized: false as const,
    decision_counts: { total: 1, pending_review: decision === null ? 1 : 0,
      reviewed: decision === 'Reviewed' ? 1 : 0, deferred: decision === 'Deferred' ? 1 : 0,
      pending_completion: decision === 'Reviewed' ? 0 : 1 },
    recommendations: [{ decision, id: 'a'.repeat(64), kind: 'review_host_discovery' as const,
      title: 'Review responding host', target_id: 'synthetic-target-0', target: '192.0.2.1',
      service: null, port: null, reason: 'A completed discovery observation recorded this host as responding.',
      source_observation_id: 'synthetic-observation', source_evidence_id: 'synthetic-evidence',
      execution_available: false as const, execution_status: 'not_supported' as const,
      suggested_test: null, suggested_tool: null,
      source_test: { test_name: 'Network Discovery', tool: 'Nmap', status: 'Completed' as const } }] }
}


export function completionReview(): CompletionReview {
  return {
    assessment_id: assessmentId, assessment_name: 'Synthetic Network Assessment', lifecycle_status: 'Testing',
    ready: true, can_complete: true, snapshot_schema_version: 2, snapshot_digest: 'b'.repeat(64),
    summary: { total: 1, counts: { Queued: 0, Running: 0, Completed: 1, Failed: 0, Stopped: 0, Blocked: 0, Cancelled: 0 },
      active_attempts: 0, active_execution_requests: 0, recovery_required_requests: 0,
      processing_errors: 0, processing_pending: 0, missing_processing: 0,
      recommendation_count: 0, pending_recommendation_ids: [], reviewed_recommendations: 0, deferred_recommendations: 0,
      decision_counts: { total: 0, pending_review: 0, reviewed: 0, deferred: 0, pending_completion: 0 },
      candidate_findings: null, blockers: [] },
    blocker_details: [], recommendations: [], completion: null,
  }
}

export function completedCompletionReview(): CompletionReview {
  const initial = completionReview()
  return { ...initial, lifecycle_status: 'Finding Review', ready: false, can_complete: false,
    snapshot_digest: 'c'.repeat(64), completion: { completed_at: '2026-11-19T10:00:00Z',
      actor_id: 'synthetic-completion-actor', snapshot: structuredClone(initial.summary) as unknown as Record<string, unknown>,
      snapshot_schema_version: 1, snapshot_digest: null } }
}

export function intelligentRecommendationData(outcome: 'Accepted' | 'Rejected' | null = null) {
  const legacy = recommendationData(outcome ? 'Reviewed' : null)
  return { ...legacy, recommendations: [{ ...legacy.recommendations[0], kind: 'evidence_followup' as const,
    title: 'HTTP Server Assessment', target: '192.0.2.1', service: 'https', port: 443,
    context_digest: 'a'.repeat(64), review_outcome: outcome,
    explanation: ['HTTPS service was observed on 192.0.2.1:443.', 'Service identification did not verify server configuration.', 'Nikto is proposed for server assessment; integration is pending.'],
    suggested_test: 'HTTP Server Assessment', suggested_tool: 'Nikto',
    tool_integration_status: 'pending_integration' as const, execution_status: 'pending_integration' as const,
    execution_unavailability_reason: 'tool_integration_pending',
    proposed_test: { id: 'http-server-assessment', version: 1, name: 'HTTP Server Assessment', tool: 'Nikto',
      description: 'Assess an evidenced HTTP server.', profile_id: null, definition_digest: 'b'.repeat(64) } }] }
}
