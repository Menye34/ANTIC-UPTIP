import { ScopeError } from './scope'

export interface BaselineAssignment {
  profile_id: string
  version: number
  tool: string
  activity: string
  status: 'pending' | 'resolved' | 'blocked' | 'requires_revalidation' | 'unavailable'
  reason_code: string
  reason: string
}

export interface Target {
  id: string
  original_value: string
  normalized_value: string
  kind: string
  scope_status: 'in_scope' | 'out_of_scope' | 'requires_revalidation'
  eligibility: 'pending' | 'blocked'
  classification_reason: string
  revision: number
  baseline_assignments?: BaselineAssignment[]
  baseline_summary?: BaselineAssignment['status'] | 'no_compatible_baseline'
}

interface TargetList {
  targets: Target[]
  can_edit: boolean
  status: string
  counts: { total: number; eligible: number; blocked: number }
}

type Change = { method: 'POST'; value: string } |
  { method: 'PATCH'; target: Target; value: string } |
  { method: 'DELETE'; target: Target }

export async function requestTargets(assessment: string, csrf: string, signal: AbortSignal, change?: Change) {
  const id = change && 'target' in change ? '/' + encodeURIComponent(change.target.id) : ''
  const url = '/api/v1/assessments/' + encodeURIComponent(assessment) + '/targets' + id
  const response = await fetch(url, {
    credentials: 'same-origin',
    signal: AbortSignal.any([signal, AbortSignal.timeout(15000)]),
    ...(change && {
      method: change.method,
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
      body: JSON.stringify({
        ...(change.method === 'DELETE' ? { confirmed: true } : { value: change.value }),
        ...('target' in change && { revision: change.target.revision }),
      }),
    }),
  })
  if (!response.ok) {
    const result = await response.json().catch(() => null)
    throw new ScopeError(response.status, result?.code)
  }
  return response.json() as Promise<TargetList>
}
