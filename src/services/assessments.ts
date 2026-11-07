export interface AssessmentDraft {
  name: string
  description: string | null
  start_date: string | null
  end_date: string | null
}

export interface Assessment extends AssessmentDraft {
  id: string
  reference: string
  status: 'Draft'
  lead_analyst: string
  created_by: string
  created_at: string
}

export class AssessmentRequestError extends Error {
  readonly status: number

  constructor(status: number) {
    super('Assessment request failed')
    this.status = status
  }
}

async function request(path: string, options: RequestInit): Promise<Assessment> {
  const response = await fetch('/api/v1/assessments' + path, {
    ...options,
    credentials: 'same-origin',
    signal: options.signal
      ? AbortSignal.any([options.signal, AbortSignal.timeout(15000)])
      : AbortSignal.timeout(15000),
  })
  if (!response.ok) throw new AssessmentRequestError(response.status)
  return response.json()
}

export function createAssessment(draft: AssessmentDraft, csrfToken: string, idempotencyKey: string, signal: AbortSignal) {
  return request('', {
    method: 'POST',
    signal,
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken, 'Idempotency-Key': idempotencyKey },
    body: JSON.stringify(draft),
  })
}

export function getAssessment(id: string, signal: AbortSignal) {
  return request('/' + encodeURIComponent(id), { signal })
}
