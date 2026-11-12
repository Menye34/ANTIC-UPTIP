export type StartMode = 'full' | 'partial'

export interface StartActivity {
  target_id: string
  profile_id: string
  activity?: string
  tool?: string
  exclusion_code?: string
}

export interface StartExcludedTarget {
  target_id: string
  reasons: Array<{ code: string; message: string }>
}

export interface StartReview {
  mode: StartMode | null
  confirmation_possible: boolean
  review_token: string | null
  expires_at: string | null
  eligible_activities: StartActivity[]
  excluded_activities: StartActivity[]
  excluded_targets: StartExcludedTarget[]
}

export interface AssessmentReadiness {
  assessment_id: string
  lifecycle_status: string
  start_review_eligible: boolean
  start_review: StartReview
  reasons: Array<{ code: string; message: string }>
  targets: Array<{
    target_id: string
    value: string
    baseline_activities: Array<{
      profile_id: string
      start_review_eligible: boolean
    }>
  }>
}

export interface StartReceipt {
  authorization_id: string
  assessment_id: string
  lifecycle_status: 'Ready'
  mode: StartMode
  confirmed_at: string
  execution_authorized: false
  authorized_activity_count: number
  authorized_target_count: number
  excluded_activity_count: number
  excluded_target_count: number
}

export class AssessmentStartError extends Error {
  readonly status: number
  readonly code?: string

  constructor(
    status: number,
    code?: string,
  ) {
    super('Assessment Start request failed')
    this.status = status
    this.code = code
  }
}

async function startRequest<T>(
  assessmentId: string,
  endpoint: string,
  signal: AbortSignal,
  options: RequestInit = {},
): Promise<T> {
  const response = await fetch(
    '/api/v1/assessments/' +
      encodeURIComponent(assessmentId) +
      endpoint,
    {
      ...options,
      credentials: 'same-origin',
      cache: 'no-store',
      signal: AbortSignal.any([
        signal,
        AbortSignal.timeout(15000),
      ]),
    },
  )

  if (!response.ok) {
    const result = await response.json().catch(() => null)
    throw new AssessmentStartError(
      response.status,
      result?.detail?.code ?? result?.code,
    )
  }

  return response.json() as Promise<T>
}

export function getAssessmentReadiness(
  assessmentId: string,
  signal: AbortSignal,
) {
  return startRequest<AssessmentReadiness>(
    assessmentId,
    '/readiness',
    signal,
  )
}

export function confirmAssessmentStart(
  assessmentId: string,
  csrfToken: string,
  review: StartReview,
  idempotencyKey: string,
  signal: AbortSignal,
) {
  if (
    !review.confirmation_possible ||
    !review.review_token ||
    !review.mode
  ) {
    throw new Error('Start Assessment confirmation is unavailable.')
  }

  return startRequest<StartReceipt>(
    assessmentId,
    '/start',
    signal,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
        'Idempotency-Key': idempotencyKey,
      },
      body: JSON.stringify({
        review_token: review.review_token,
        mode: review.mode,
        confirmed: true,
      }),
    },
  )
}
