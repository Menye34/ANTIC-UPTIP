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
