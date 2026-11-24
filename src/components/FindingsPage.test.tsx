import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import FindingsPage from './FindingsPage'
import type { Assessment } from '../services/assessments'
import type { ConsolidatedFinding } from './FindingsPage'

const assessment: Assessment = {
  id: 'synthetic-assessment',
  name: 'Synthetic Network Assessment',
  reference: 'SYN-001',
  status: 'Finding Review',
  description: null,
  start_date: null,
  end_date: null,
  lead_analyst: 'Test Analyst',
  created_by: 'synthetic-analyst',
  created_at: '2026-11-19T10:00:00Z',
}
const reply = (value: unknown, status = 200) => ({ ok: status < 400, status, json: async () => value })
const expired = vi.fn()
const back = vi.fn()
afterEach(() => { cleanup(); vi.unstubAllGlobals(); expired.mockReset(); back.mockReset() })
function renderPage() { return render(<FindingsPage assessmentId={assessment.id} onExpired={expired} onTesting={back} />) }

it('loads an authorized assessment and does not invent candidate findings', async () => {
  const fetcher = vi.fn(async (url: string) => reply(url.endsWith('/findings') ? { assessment_id: assessment.id, lifecycle_status: 'Finding Review', total: 0, counts: { Critical: 0, High: 0, Medium: 0, Low: 0 }, findings: [] } : assessment))
  vi.stubGlobal('fetch', fetcher)
  renderPage()
  expect(await screen.findByRole('heading', { name: 'Findings' })).toBeVisible()
  expect(await screen.findByText('No findings yet')).toBeVisible()
  expect(screen.getByText(/No consolidated security issues were recorded/)).toBeVisible()
  expect(screen.getAllByText('0')).toHaveLength(5)
  expect(fetcher).toHaveBeenCalledWith('/api/v1/assessments/' + assessment.id,
    expect.objectContaining({ credentials: 'same-origin' }))
  fireEvent.click(screen.getByRole('button', { name: /Add Manual Finding/ }))
  expect(screen.getByRole('dialog', { name: 'Add Manual Finding' })).toBeVisible()
  expect(screen.getByText(/No finding will be saved/)).toBeVisible()
})

it('does not claim Finding Review when the persisted lifecycle is Testing', async () => {
  vi.stubGlobal('fetch', vi.fn(async (url: string) => reply(url.endsWith('/findings') ? { assessment_id: assessment.id, lifecycle_status: 'Testing', total: 0, counts: { Critical: 0, High: 0, Medium: 0, Low: 0 }, findings: [] } : { ...assessment, status: 'Testing' })))
  renderPage()
  expect(await screen.findByText(/Current status: Testing/)).toBeVisible()
  expect(screen.getByText('No findings yet')).toBeVisible()
})

it('handles denied access without showing protected assessment details', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => reply({}, 404)))
  renderPage()
  expect(await screen.findByRole('alert')).toHaveTextContent('Assessment unavailable')
  expect(screen.queryByText(assessment.name)).not.toBeInTheDocument()
})

it('ends the session on authentication expiry', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => reply({}, 401)))
  renderPage()
  expect(await screen.findByRole('alert')).toBeVisible()
  expect(expired).toHaveBeenCalledTimes(1)
})

const sample: ConsolidatedFinding = {
  id: 'synthetic-finding', title: 'Content Security Policy (CSP) Header Not Set',
  severity: 'Medium', affectedTarget: 'https://app.example.test', source: 'OWASP ZAP',
  sourceTest: 'Web Application Scan', description: 'The Content-Security-Policy header is missing.',
  impact: 'Content injection exposure', securityControl: 'Content-Security-Policy',
  observedCondition: 'HTTP response does not include the header.',
  detectedIssue: 'Content-Security-Policy header missing',
  remediation: 'Implement and test a Content Security Policy.',
}
it('renders populated F-01 metrics, filters and detail navigation with supplied frontend data', async () => {
  const navigate = vi.fn()
  vi.stubGlobal('fetch', vi.fn(async () => reply(assessment)))
  render(<FindingsPage assessmentId={assessment.id} onExpired={expired} onTesting={back}
    findings={[sample]} onFinding={navigate} />)
  expect(await screen.findByText(sample.title)).toBeVisible()
  expect(screen.getByText('Showing 1 of 1 findings')).toBeVisible()
  fireEvent.change(screen.getByPlaceholderText('Search by finding title or affected target'), { target: { value: 'not present' } })
  expect(screen.getByText('No findings match your filters.')).toBeVisible()
  fireEvent.change(screen.getByPlaceholderText('Search by finding title or affected target'), { target: { value: '' } })
  fireEvent.click(screen.getByRole('button', { name: 'View Details' }))
  expect(navigate).toHaveBeenCalledWith(sample.id)
})
it('renders F-02 details and an unavailable AI state without fabricated advice', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => reply(assessment)))
  render(<FindingsPage assessmentId={assessment.id} onExpired={expired} onTesting={back}
    findings={[sample]} findingId={sample.id} onBack={back} />)
  expect(await screen.findByRole('heading', { name: sample.title })).toBeVisible()
  expect(screen.getByRole('heading', { name: 'Finding Information' })).toBeVisible()
  expect(screen.getByRole('heading', { name: 'Supporting Evidence' })).toBeVisible()
  expect(screen.getByText('Original Tool Output').closest('details')).not.toHaveAttribute('open')
  fireEvent.click(screen.getByRole('button', { name: 'Ask AI About This Finding' }))
  expect(screen.getByRole('dialog', { name: 'AI Assistant' })).toBeVisible()
  fireEvent.click(screen.getByRole('button', { name: /Suggest a fix/ }))
  expect(screen.getByText('AI Assistant is unavailable')).toBeVisible()
  fireEvent.click(screen.getByRole('button', { name: 'Close AI Assistant' }))
  fireEvent.click(screen.getByRole('button', { name: /Back to Findings/ }))
  expect(back).toHaveBeenCalledTimes(1)
})

it('loads real backend findings instead of showing zero by default', async () => {
  const navigate = vi.fn()
  const fetcher = vi.fn(async (url: string) => reply(url.endsWith('/findings')
    ? { assessment_id: assessment.id, lifecycle_status: 'Finding Review', total: 1,
        counts: { Critical: 0, High: 0, Medium: 1, Low: 0 },
        findings: [{ id: sample.id, title: sample.title, severity: sample.severity,
          affected_target: sample.affectedTarget, source: sample.source }] }
    : assessment))
  vi.stubGlobal('fetch', fetcher)
  render(<FindingsPage assessmentId={assessment.id} onExpired={expired}
    onTesting={back} onFinding={navigate} />)
  expect(await screen.findByText(sample.title)).toBeVisible()
  expect(screen.getByText('Showing 1 of 1 findings')).toBeVisible()
  expect(screen.queryByText('No findings yet')).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'View Details' }))
  expect(navigate).toHaveBeenCalledWith(sample.id)
  expect(fetcher).toHaveBeenCalledWith('/api/v1/assessments/' + assessment.id + '/findings',
    expect.objectContaining({ credentials: 'same-origin' }))
})

it('does not show a misleading zero count when findings API fails', async () => {
  vi.stubGlobal('fetch', vi.fn(async (url: string) => reply(
    url.endsWith('/findings') ? {} : assessment,
    url.endsWith('/findings') ? 503 : 200)))
  renderPage()
  expect(await screen.findByRole('alert')).toHaveTextContent('Unable to load verified findings')
  expect(screen.queryByText('No findings yet')).not.toBeInTheDocument()
})

it('loads F-02 details from the assessment-scoped API', async () => {
  const fetcher = vi.fn(async (url: string) => reply(
    url.endsWith('/findings/' + sample.id)
      ? { id: sample.id, title: sample.title, severity: sample.severity,
          affected_target: sample.affectedTarget, source: sample.source,
          source_test: sample.sourceTest, description: sample.description,
          impact: sample.impact, security_control: sample.securityControl,
          observed_condition: sample.observedCondition,
          detected_issue: sample.detectedIssue, remediation: sample.remediation }
      : url.endsWith('/findings')
        ? { assessment_id: assessment.id, lifecycle_status: 'Finding Review', total: 1,
            counts: { Critical: 0, High: 0, Medium: 1, Low: 0 },
            findings: [{ id: sample.id, title: sample.title, severity: sample.severity,
              affected_target: sample.affectedTarget, source: sample.source }] }
        : assessment))
  vi.stubGlobal('fetch', fetcher)
  render(<FindingsPage assessmentId={assessment.id} onExpired={expired}
    onTesting={back} findingId={sample.id} />)
  expect(await screen.findByRole('heading', { name: sample.title })).toBeVisible()
  expect(screen.getByText(sample.remediation)).toBeVisible()
  await waitFor(() => expect(fetcher).toHaveBeenCalledWith(
    '/api/v1/assessments/' + assessment.id + '/findings/' + sample.id,
    expect.objectContaining({ credentials: 'same-origin' })))
})

it('rejects malformed findings without crashing or displaying misleading counts', async () => {
  vi.stubGlobal('fetch', vi.fn(async (url: string) => reply(url.endsWith('/findings')
    ? { assessment_id: assessment.id, lifecycle_status: 'Finding Review', total: 1,
        findings: [{ id: 'bad', severity: 'Medium', source: 'Nmap' }] }
    : assessment)))
  renderPage()
  expect(await screen.findByRole('alert')).toHaveTextContent('Unable to load verified findings')
  expect(screen.queryByText('No findings yet')).not.toBeInTheDocument()
})

it('distinguishes an unavailable F-02 finding from a temporary failure', async () => {
  vi.stubGlobal('fetch', vi.fn(async (url: string) => url.endsWith('/findings/missing')
    ? reply({}, 404)
    : reply(url.endsWith('/findings')
      ? { assessment_id: assessment.id, lifecycle_status: 'Finding Review', total: 0, findings: [] }
      : assessment)))
  render(<FindingsPage assessmentId={assessment.id} onExpired={expired}
    onTesting={back} findingId="missing" />)
  expect(await screen.findByText('Finding unavailable for this assessment.')).toBeVisible()
})


const verifiedSummary = {
  id: sample.id,
  title: sample.title,
  severity: sample.severity,
  affected_target: sample.affectedTarget,
  source: sample.source,
}

const verifiedOverview = {
  assessment_id: assessment.id,
  lifecycle_status: 'Finding Review',
  total: 1,
  counts: { Critical: 0, High: 0, Medium: 1, Low: 0 },
  findings: [verifiedSummary],
}

const verifiedDetail = {
  ...verifiedSummary,
  source_test: sample.sourceTest,
  description: sample.description,
  impact: sample.impact,
  security_control: sample.securityControl,
  observed_condition: sample.observedCondition,
  detected_issue: sample.detectedIssue,
  remediation: sample.remediation,
}

it.each([
  ['wrong assessment', {
    ...verifiedOverview,
    assessment_id: 'different-assessment',
  }],
  ['incorrect total', {
    ...verifiedOverview,
    total: 2,
  }],
  ['incorrect severity counts', {
    ...verifiedOverview,
    counts: { Critical: 0, High: 1, Medium: 0, Low: 0 },
  }],
  ['duplicate findings', {
    ...verifiedOverview,
    total: 2,
    counts: { Critical: 0, High: 0, Medium: 2, Low: 0 },
    findings: [verifiedSummary, verifiedSummary],
  }],
])('rejects an inconsistent overview: %s', async (_reason, value) => {
  vi.stubGlobal('fetch', vi.fn(async (url: string) =>
    reply(url.endsWith('/findings') ? value : assessment)))
  renderPage()
  expect(await screen.findByRole('alert'))
    .toHaveTextContent('Unable to load verified findings')
  expect(screen.queryByText(sample.title)).not.toBeInTheDocument()
  expect(screen.queryByText('No findings yet')).not.toBeInTheDocument()
})

it('rejects an assessment response belonging to another assessment', async () => {
  vi.stubGlobal('fetch', vi.fn(async (url: string) =>
    reply(url.endsWith('/findings')
      ? verifiedOverview
      : { ...assessment, id: 'different-assessment', name: 'Unrelated assessment' })))
  renderPage()
  expect(await screen.findByRole('alert')).toBeVisible()
  expect(screen.queryByText('Unrelated assessment')).not.toBeInTheDocument()
})

it.each([
  ['wrong finding identity', { ...verifiedDetail, id: 'different-finding' }],
  ['missing remediation', { ...verifiedDetail, remediation: '' }],
])('rejects an invalid finding detail: %s', async (_reason, value) => {
  vi.stubGlobal('fetch', vi.fn(async (url: string) =>
    reply(url.endsWith('/findings/' + sample.id)
      ? value
      : url.endsWith('/findings') ? verifiedOverview : assessment)))
  render(<FindingsPage assessmentId={assessment.id}
    onExpired={expired} onTesting={back} findingId={sample.id} />)
  expect(await screen.findByRole('alert')).toBeVisible()
  expect(screen.queryByRole('heading', { name: sample.title }))
    .not.toBeInTheDocument()
})


// AI Assistant functional integration tests

const aiScope = {
  assessment_id: assessment.id,
  finding_id: sample.id,
}

const aiContent = {
  action: 'suggest_fix',
  question: 'Suggest a fix',
  answer: 'Configure and test an appropriate Content Security Policy.',
  model: 'qwen2.5:3b',
  output_tokens: 12,
  evidence: [{
    observation_id: '10000000-0000-4000-8000-000000000001',
    evidence_id: '20000000-0000-4000-8000-000000000001',
    source: 'OWASP ZAP',
  }],
  limitations: ['AI-generated advice requires analyst review.'],
  advisory_only: true,
}

const aiAnswer = {
  ...aiScope,
  ...aiContent,
  status: 'answered',
  history_id: '30000000-0000-4000-8000-000000000001',
}

const aiHistoryEntry = {
  ...aiContent,
  id: aiAnswer.history_id,
  prompt_version: 'finding-assistance-v1',
  created_at: '2026-11-24T10:00:00Z',
}

const aiUnavailable = {
  status: 'unavailable',
  code: 'ai_service_unavailable',
  message: 'The AI service is temporarily unavailable.',
  retryable: true,
}

function historyReply(
  entries: unknown[] = [],
  offset = 0,
  hasMore = false,
) {
  return reply({
    ...aiScope,
    entries,
    limit: 20,
    offset,
    has_more: hasMore,
  })
}

type MockReply = ReturnType<typeof reply>

function installAIFetch(
  ask: (options?: RequestInit) => MockReply | Promise<MockReply>,
  history: (url: string) => MockReply | Promise<MockReply> =
    () => historyReply(),
) {
  const fetcher = vi.fn(async (
    url: string,
    options?: RequestInit,
  ) => {
    if (url.endsWith('/ai/ask')) return ask(options)
    if (url.includes('/ai/history?')) return history(url)
    return reply(assessment)
  })

  vi.stubGlobal('fetch', fetcher)

  return fetcher
}

async function openAI() {
  const view = render(
    <FindingsPage
      assessmentId={assessment.id}
      csrfToken="synthetic-csrf"
      onExpired={expired}
      onTesting={back}
      findings={[sample]}
      findingId={sample.id}
      onBack={back}
    />
  )

  await screen.findByRole('heading', { name: sample.title })

  const trigger = screen.getByRole('button', {
    name: 'Ask AI About This Finding',
  })

  trigger.focus()
  fireEvent.click(trigger)

  await screen.findByRole('dialog', { name: 'AI Assistant' })

  return { ...view, trigger }
}

function askForFix() {
  fireEvent.click(screen.getByRole('button', {
    name: /Suggest a fix/,
  }))
}

it('AI-01 displays all quick actions and empty history', async () => {
  const ask = vi.fn(() => reply(aiAnswer))
  installAIFetch(ask)

  await openAI()

  for (const label of [
    'Explain this finding',
    'Explain the potential impact',
    'Suggest a fix',
    'Help write the description',
    'Explain the tool output',
  ]) {
    expect(screen.getByRole('button', {
      name: new RegExp(label),
    })).toBeVisible()
  }

  expect(await screen.findByText(
    'No questions have been asked about this finding yet.'
  )).toBeVisible()

  expect(ask).not.toHaveBeenCalled()
})

it('AI-02 prevents duplicate submissions while working', async () => {
  let finish!: (value: MockReply) => void

  const pending = new Promise<MockReply>(resolve => {
    finish = resolve
  })

  const ask = vi.fn(() => pending)

  installAIFetch(ask)
  await openAI()
  askForFix()

  expect(await screen.findByText(
    'Reading the finding and its evidence…'
  )).toBeVisible()

  expect(screen.getByRole('button', {
    name: 'Ask',
  })).toBeDisabled()

  expect(screen.getByPlaceholderText(
    'Ask about this finding…'
  )).toBeDisabled()

  expect(ask).toHaveBeenCalledTimes(1)

  finish(reply(aiAnswer))

  expect(await screen.findByText(aiContent.answer))
    .toBeVisible()
})

it('AI-03 displays the verified answer and evidence', async () => {
  installAIFetch(() => reply(aiAnswer))

  await openAI()
  askForFix()

  expect(await screen.findByText(aiContent.answer))
    .toBeVisible()

  expect(screen.getByText('Evidence used')).toBeVisible()

  expect(screen.getByText(
    'OWASP ZAP — Supporting observation'
  )).toBeVisible()

  expect(screen.getByText('Limitations')).toBeVisible()
})

it('AI-04 displays insufficient evidence without an invented answer', async () => {
  installAIFetch(() => reply({
    ...aiScope,
    status: 'insufficient_evidence',
    action: 'suggest_fix',
    message: 'Supporting evidence is insufficient.',
  }))

  await openAI()
  askForFix()

  expect(await screen.findByText('Not enough evidence'))
    .toBeVisible()

  expect(screen.getByText(
    'Supporting evidence is insufficient.'
  )).toBeVisible()

  expect(screen.queryByText(aiContent.answer))
    .not.toBeInTheDocument()
})

it('AI-05 supports explicit retry after a retryable failure', async () => {
  const ask = vi.fn()
    .mockResolvedValueOnce(reply(aiUnavailable))
    .mockResolvedValueOnce(reply(aiAnswer))

  installAIFetch(ask)

  await openAI()
  askForFix()

  expect(await screen.findByText(
    'AI Assistant is unavailable'
  )).toBeVisible()

  expect(ask).toHaveBeenCalledTimes(1)

  fireEvent.click(screen.getByRole('button', {
    name: 'Try Again',
  }))

  expect(await screen.findByText(aiContent.answer))
    .toBeVisible()

  expect(ask).toHaveBeenCalledTimes(2)
})

it('sends a custom question with the authenticated CSRF token', async () => {
  const question = 'How should this finding be documented?'

  const fetcher = installAIFetch(() => reply({
    ...aiAnswer,
    action: 'custom',
    question,
  }))

  await openAI()

  fireEvent.change(screen.getByPlaceholderText(
    'Ask about this finding…'
  ), {
    target: { value: '  ' + question + '  ' },
  })

  fireEvent.click(screen.getByRole('button', {
    name: 'Ask',
  }))

  expect(await screen.findByText(aiContent.answer))
    .toBeVisible()

  expect(fetcher).toHaveBeenCalledWith(
    '/api/v1/assessments/' + assessment.id +
    '/findings/' + sample.id + '/ai/ask',
    expect.objectContaining({
      method: 'POST',
      credentials: 'same-origin',
      headers: expect.objectContaining({
        'X-CSRF-Token': 'synthetic-csrf',
      }),
      body: JSON.stringify({
        action: 'custom',
        question,
      }),
    })
  )
})

it('loads and reopens saved history without new inference', async () => {
  const ask = vi.fn(() => reply(aiAnswer))

  installAIFetch(
    ask,
    () => historyReply([aiHistoryEntry]),
  )

  await openAI()

  const saved = await screen.findByRole('button', {
    name: /Suggest a fix.*2026/,
  })

  fireEvent.click(saved)

  expect(screen.getByText(aiContent.answer)).toBeVisible()
  expect(ask).not.toHaveBeenCalled()
})

it('loads additional history using the correct pagination offset', async () => {
  const entries = Array.from({ length: 20 }, (_, index) => ({
    ...aiHistoryEntry,
    id: '30000000-0000-4000-8000-' +
      String(index + 1).padStart(12, '0'),
    question: 'Saved question ' + (index + 1),
  }))

  const additional = {
    ...aiHistoryEntry,
    id: '30000000-0000-4000-8000-000000000021',
    question: 'Additional saved question',
  }

  const history = vi.fn((url: string) =>
    url.includes('offset=20')
      ? historyReply([additional], 20)
      : historyReply(entries, 0, true)
  )

  installAIFetch(() => reply(aiAnswer), history)

  await openAI()

  fireEvent.click(await screen.findByRole('button', {
    name: 'Load more',
  }))

  expect(await screen.findByText(
    'Additional saved question'
  )).toBeVisible()

  expect(screen.getByText('Saved question 1')).toBeVisible()

  expect(history).toHaveBeenCalledWith(
    expect.stringContaining('offset=20')
  )
})

it('reports session expiration during an AI request', async () => {
  installAIFetch(() => reply({}, 401))

  await openAI()
  askForFix()

  await waitFor(() => {
    expect(expired).toHaveBeenCalledTimes(1)
  })

  expect(screen.queryByText(aiContent.answer))
    .not.toBeInTheDocument()
})

it.each([403, 404])(
  'does not display protected AI answers after HTTP %s',
  async status => {
    installAIFetch(() => reply({}, status))

    await openAI()
    askForFix()

    expect(await screen.findByText(
      'AI assistance is unavailable for this finding.'
    )).toBeVisible()

    expect(screen.queryByText(aiContent.answer))
      .not.toBeInTheDocument()

    expect(screen.queryByRole('button', {
      name: 'Try Again',
    })).not.toBeInTheDocument()
  }
)

it('cancels the pending browser request when the panel closes', async () => {
  let requestSignal: AbortSignal | null | undefined
  let finish!: (value: MockReply) => void

  const pending = new Promise<MockReply>(resolve => {
    finish = resolve
  })

  installAIFetch(options => {
    requestSignal = options?.signal
    return pending
  })

  await openAI()
  askForFix()

  await screen.findByText(
    'Reading the finding and its evidence…'
  )

  fireEvent.click(screen.getByRole('button', {
    name: 'Close AI Assistant',
  }))

  expect(requestSignal?.aborted).toBe(true)

  expect(screen.queryByRole('dialog', {
    name: 'AI Assistant',
  })).not.toBeInTheDocument()

  finish(reply(aiAnswer))
})

it('supports Escape dismissal and restores focus', async () => {
  installAIFetch(() => reply(aiAnswer))

  const { trigger } = await openAI()

  expect(screen.getByRole('button', {
    name: 'Close AI Assistant',
  })).toHaveFocus()

  fireEvent.keyDown(document, { key: 'Escape' })

  expect(screen.queryByRole('dialog', {
    name: 'AI Assistant',
  })).not.toBeInTheDocument()

  expect(trigger).toHaveFocus()
})

it('rejects an answer belonging to another finding', async () => {
  installAIFetch(() => reply({
    ...aiAnswer,
    finding_id: 'unrelated-finding',
  }))

  await openAI()
  askForFix()

  expect(await screen.findByText(
    'AI Assistant is unavailable'
  )).toBeVisible()

  expect(screen.queryByText(aiContent.answer))
    .not.toBeInTheDocument()
})

it('does not automatically retry an uncertain request', async () => {
  const ask = vi.fn(async () => {
    throw new Error('Synthetic network failure')
  })

  installAIFetch(ask)

  await openAI()
  askForFix()

  expect(await screen.findByText(
    /The request outcome could not be confirmed/
  )).toBeVisible()

  expect(ask).toHaveBeenCalledTimes(1)

  expect(screen.queryByRole('button', {
    name: 'Try Again',
  })).not.toBeInTheDocument()
})
