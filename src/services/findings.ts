import { AssessmentRequestError } from './assessments'

export type FindingSeverity = 'Critical' | 'High' | 'Medium' | 'Low'

export interface FindingSummary {
  id: string
  title: string
  severity: FindingSeverity
  affected_target: string
  source: string
}

export interface FindingsOverview {
  assessment_id: string
  lifecycle_status: string
  total: number
  counts: Record<FindingSeverity, number>
  findings: FindingSummary[]
}

export interface FindingDetail extends FindingSummary {
  source_test: string
  description: string
  impact: string
  security_control: string
  observed_condition: string
  detected_issue: string
  remediation: string
}

async function get<T>(path: string, signal: AbortSignal): Promise<T> {
  const response = await fetch('/api/v1/assessments/' + path, {
    credentials: 'same-origin',
    signal: AbortSignal.any([signal, AbortSignal.timeout(15000)]),
  })
  if (!response.ok) throw new AssessmentRequestError(response.status)
  return response.json() as Promise<T>
}

export function getFindingsOverview(assessmentId: string, signal: AbortSignal) {
  return get<FindingsOverview>(encodeURIComponent(assessmentId) + '/findings', signal)
}

export function getFindingDetail(assessmentId: string, findingId: string, signal: AbortSignal) {
  return get<FindingDetail>(encodeURIComponent(assessmentId) + '/findings/' + encodeURIComponent(findingId), signal)
}
