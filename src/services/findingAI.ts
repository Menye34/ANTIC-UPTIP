import { AssessmentRequestError } from './assessments'

export const aiActions = [
  'explain_finding',
  'explain_impact',
  'suggest_fix',
  'write_description',
  'explain_tool_output',
  'custom',
] as const

export type AIAction = typeof aiActions[number]

export type AIRequest =
  | { action: Exclude<AIAction, 'custom'> }
  | { action: 'custom'; question: string }

export interface AIEvidenceReference {
  observation_id: string
  evidence_id: string
  source: string
}

interface AIAnswerContent {
  action: AIAction
  question: string
  answer: string
  model: string
  output_tokens: number
  evidence: AIEvidenceReference[]
  limitations: string[]
  advisory_only: true
}

export interface AIAnswer extends AIAnswerContent {
  status: 'answered'
  history_id: string
  assessment_id: string
  finding_id: string
}

export interface AIInsufficientEvidence {
  status: 'insufficient_evidence'
  assessment_id: string
  finding_id: string
  action: AIAction
  message: string
}

export interface AIUnavailable {
  status: 'unavailable'
  code: string
  message: string
  retryable: boolean
}

export type AIResponse =
  | AIAnswer
  | AIInsufficientEvidence
  | AIUnavailable

export interface AIHistoryEntry extends AIAnswerContent {
  id: string
  prompt_version: string
  created_at: string
}

export interface AIHistoryResponse {
  assessment_id: string
  finding_id: string
  entries: AIHistoryEntry[]
  limit: number
  offset: number
  has_more: boolean
}

type ObjectValue = Record<string, unknown>

const object = (v: unknown): v is ObjectValue =>
  v !== null && typeof v === 'object' && !Array.isArray(v)

const text = (v: unknown, max: number): v is string =>
  typeof v === 'string' && v.trim().length > 0 && v.length <= max

const uuid = (v: unknown): v is string =>
  typeof v === 'string' &&
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v)

const action = (v: unknown): v is AIAction =>
  aiActions.includes(v as AIAction)

const integer = (v: unknown, min: number, max: number): boolean =>
  Number.isSafeInteger(v) && Number(v) >= min && Number(v) <= max

function validContent(v: ObjectValue): boolean {
  return action(v.action)
    && text(v.question, 500)
    && text(v.answer, 6000)
    && text(v.model, 100)
    && integer(v.output_tokens, 1, 512)
    && v.advisory_only === true
    && Array.isArray(v.evidence)
    && v.evidence.length >= 1
    && v.evidence.length <= 3
    && v.evidence.every(e =>
      object(e)
      && uuid(e.observation_id)
      && uuid(e.evidence_id)
      && text(e.source, 100))
    && Array.isArray(v.limitations)
    && v.limitations.length <= 8
    && v.limitations.every(item => typeof item === 'string')
}

export function validateAIResponse(
  value: unknown,
  assessmentId: string,
  findingId: string,
  request: AIRequest,
): AIResponse {
  const invalid = () => {
    throw new Error('Invalid AI assistance response')
  }

  if (!object(value)) return invalid()

  if (value.status === 'unavailable') {
    if (!text(value.code, 80)
      || !text(value.message, 500)
      || typeof value.retryable !== 'boolean') return invalid()
    return value as unknown as AIUnavailable
  }

  if (value.assessment_id !== assessmentId
    || value.finding_id !== findingId
    || value.action !== request.action) return invalid()

  if (value.status === 'insufficient_evidence') {
    if (!text(value.message, 500)) return invalid()
    return value as unknown as AIInsufficientEvidence
  }

  if (value.status !== 'answered'
    || !uuid(value.history_id)
    || !validContent(value)
    || (request.action === 'custom'
      && value.question !== request.question.trim())) return invalid()

  return value as unknown as AIAnswer
}

export function validateAIHistory(
  value: unknown,
  assessmentId: string,
  findingId: string,
  limit: number,
  offset: number,
): AIHistoryResponse {
  const invalid = () => {
    throw new Error('Invalid AI history response')
  }

  if (!object(value)
    || value.assessment_id !== assessmentId
    || value.finding_id !== findingId
    || value.limit !== limit
    || value.offset !== offset
    || typeof value.has_more !== 'boolean'
    || !Array.isArray(value.entries)
    || value.entries.length > limit
    || (value.has_more && value.entries.length !== limit)
    || !value.entries.every(entry =>
      object(entry)
      && uuid(entry.id)
      && validContent(entry)
      && text(entry.prompt_version, 80)
      && typeof entry.created_at === 'string'
      && Number.isFinite(Date.parse(entry.created_at)))
    || new Set(value.entries.map(entry => entry.id)).size
      !== value.entries.length) return invalid()

  return value as unknown as AIHistoryResponse
}

function basePath(assessmentId: string, findingId: string): string {
  return '/api/v1/assessments/'
    + encodeURIComponent(assessmentId)
    + '/findings/'
    + encodeURIComponent(findingId)
    + '/ai'
}

export async function askFindingAI(
  assessmentId: string,
  findingId: string,
  request: AIRequest,
  csrfToken: string,
  signal: AbortSignal,
): Promise<AIResponse> {
  if (!csrfToken) throw new Error('Missing CSRF token')

  if (!action(request.action)) throw new Error('Invalid AI action')

  const payload = request.action === 'custom'
    ? { action: request.action, question: request.question.trim() }
    : { action: request.action }

  if (payload.action === 'custom'
    && (!('question' in payload)
      || !text(payload.question, 500))) {
    throw new Error('Invalid AI question')
  }

  const response = await fetch(
    basePath(assessmentId, findingId) + '/ask',
    {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.any([
        signal,
        AbortSignal.timeout(330000),
      ]),
    },
  )

  if (!response.ok) {
    throw new AssessmentRequestError(response.status)
  }

  return validateAIResponse(
    await response.json(),
    assessmentId,
    findingId,
    request,
  )
}

export async function getFindingAIHistory(
  assessmentId: string,
  findingId: string,
  signal: AbortSignal,
  limit = 20,
  offset = 0,
): Promise<AIHistoryResponse> {
  if (!integer(limit, 1, 50)
    || !integer(offset, 0, 10000)) {
    throw new Error('Invalid history pagination')
  }

  const response = await fetch(
    basePath(assessmentId, findingId)
      + '/history?limit=' + limit + '&offset=' + offset,
    {
      credentials: 'same-origin',
      signal: AbortSignal.any([
        signal,
        AbortSignal.timeout(15000),
      ]),
    },
  )

  if (!response.ok) {
    throw new AssessmentRequestError(response.status)
  }

  return validateAIHistory(
    await response.json(),
    assessmentId,
    findingId,
    limit,
    offset,
  )
}
