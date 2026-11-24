import { useEffect, useMemo, useRef, useState } from 'react'
import { AssessmentRequestError, getAssessment } from '../services/assessments'
import type { Assessment } from '../services/assessments'
import './FindingsPage.css'
import { askFindingAI, getFindingAIHistory } from '../services/findingAI'
import type { AIRequest, AIResponse, AIHistoryEntry } from '../services/findingAI'
import { getFindingsOverview, getFindingDetail } from '../services/findings'
import type { FindingSummary, FindingDetail } from '../services/findings'

export type FindingSeverity = 'Critical' | 'High' | 'Medium' | 'Low'
export type ConsolidatedFinding = {
  id: string; title: string; severity: FindingSeverity; affectedTarget: string; source: string
  sourceTest: string; description: string; impact: string; securityControl: string
  observedCondition: string; detectedIssue: string; remediation: string; originalToolOutput?: string
}
type Props = {
  assessmentId: string; csrfToken?: string; onExpired: () => void; onTesting: () => void
  findingId?: string; onFinding?: (id: string) => void; onBack?: () => void
  /** Optional test fixture; production fetches assessment-scoped findings from the API. */
  findings?: ConsolidatedFinding[]
}
const levels: FindingSeverity[] = ['Critical', 'High', 'Medium', 'Low']

export default function FindingsPage({ assessmentId, csrfToken = '', onExpired, onTesting, findingId, onFinding, onBack, findings: suppliedFindings }: Props) {
  const expiredReported = useRef(false)
  const reportExpiry = () => { if (!expiredReported.current) { expiredReported.current = true; onExpired() } }
  useEffect(() => { expiredReported.current = false }, [assessmentId])
  const [assessment, setAssessment] = useState<Assessment>()
  const [apiFindings, setApiFindings] = useState<ConsolidatedFinding[]>([])
  const [findingDetail, setFindingDetail] = useState<ConsolidatedFinding>()
  const [findingsLoading, setFindingsLoading] = useState(true)
  const [findingsError, setFindingsError] = useState('')
  const [detailLoading, setDetailLoading] = useState(false)
  const [detailError, setDetailError] = useState('')
  const findings = suppliedFindings ?? apiFindings
  const [error, setError] = useState('')
  const [retry, setRetry] = useState(0)
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('')
  const [source, setSource] = useState('')
  const [assistantOpen, setAssistantOpen] = useState(false)
  const [question, setQuestion] = useState('')
  const [selectedQuestion, setSelectedQuestion] = useState('')
  const [aiWorking, setAIWorking] = useState(false)
  const [aiResponse, setAIResponse] = useState<AIResponse>()
  const [savedAnswer, setSavedAnswer] = useState<AIHistoryEntry>()
  const [aiHistory, setAIHistory] = useState<AIHistoryEntry[]>([])
  const [historyLoading, setHistoryLoading] = useState(false)
  const [historyError, setHistoryError] = useState(false)
  const [historyMore, setHistoryMore] = useState(false)
  const [historyOffset, setHistoryOffset] = useState(0)
  const aiRequest = useRef<AbortController | null>(null)
  const historyRequest = useRef<AbortController | null>(null)
  const lastAIRequest = useRef<AIRequest | null>(null)
  const expiryHandler = useRef(onExpired)

  useEffect(() => {
    expiryHandler.current = onExpired
  }, [onExpired])
  const [manualOpen, setManualOpen] = useState(false)

  useEffect(() => {
    const controller = new AbortController()
    setAssessment(undefined)
    setError('')
    void getAssessment(assessmentId, controller.signal).then(result => {
      if (!controller.signal.aborted) {
        if (result.id !== assessmentId) {
          throw new Error('Assessment identity mismatch')
        }
        setAssessment(result)
      }
    }).catch((failure: unknown) => {
      if (controller.signal.aborted) return
      if (failure instanceof AssessmentRequestError && failure.status === 401) reportExpiry()
      setError(failure instanceof AssessmentRequestError && [403, 404].includes(failure.status)
        ? 'Assessment unavailable.' : 'Unable to load the assessment. Try again.')
    })
    return () => controller.abort()
  }, [assessmentId, onExpired, retry])

  useEffect(() => {
    if (suppliedFindings !== undefined) {
      setFindingsLoading(false)
      setFindingsError('')
      return
    }
    const controller = new AbortController()
    setApiFindings([])
    setFindingsLoading(true)
    setFindingsError('')
    void getFindingsOverview(assessmentId, controller.signal).then(result => {
      if (controller.signal.aborted) return
      if (!result || result.assessment_id !== assessmentId ||
          typeof result.lifecycle_status !== 'string' ||
          !Array.isArray(result.findings) ||
          !Number.isSafeInteger(result.total) ||
          result.total !== result.findings.length ||
          result.findings.some(f => !f ||
            ![f.id, f.title, f.affected_target, f.source].every(
              value => typeof value === 'string' && value.trim().length > 0
            ) || !levels.includes(f.severity)) ||
          new Set(result.findings.map(f => f.id)).size !== result.findings.length ||
          !result.counts ||
          levels.some(level =>
            !Number.isSafeInteger(result.counts[level]) ||
            result.counts[level] !== result.findings.filter(
              f => f.severity === level
            ).length
          )) throw new Error('Invalid findings response')
      setApiFindings(result.findings.map((f: FindingSummary) => ({
        id: f.id, title: f.title, severity: f.severity, affectedTarget: f.affected_target,
        source: f.source, sourceTest: '', description: '', impact: '',
        securityControl: '', observedCondition: '', detectedIssue: '', remediation: '',
      })))
    }).catch((failure: unknown) => {
      if (controller.signal.aborted) return
      if (failure instanceof AssessmentRequestError && failure.status === 401) reportExpiry()
      setFindingsError('Unable to load verified findings. Please retry.')
    }).finally(() => { if (!controller.signal.aborted) setFindingsLoading(false) })
    return () => controller.abort()
  }, [assessmentId, onExpired, retry, suppliedFindings])

  useEffect(() => {
    if (!findingId || suppliedFindings !== undefined) {
      setFindingDetail(undefined)
      setDetailLoading(false)
      setDetailError('')
      return
    }
    const controller = new AbortController()
    setFindingDetail(undefined)
    setDetailLoading(true)
    setDetailError('')
    void getFindingDetail(assessmentId, findingId, controller.signal).then((f: FindingDetail) => {
      if (controller.signal.aborted) return
      if (!f || f.id !== findingId ||
          !levels.includes(f.severity) ||
          ![f.id, f.title, f.affected_target, f.source,
            f.source_test, f.description, f.impact,
            f.security_control, f.observed_condition,
            f.detected_issue, f.remediation].every(
              value => typeof value === 'string' && value.trim().length > 0
          )) throw new Error('Invalid finding detail')
      setFindingDetail({
        id: f.id, title: f.title, severity: f.severity, affectedTarget: f.affected_target,
        source: f.source, sourceTest: f.source_test, description: f.description,
        impact: f.impact, securityControl: f.security_control,
        observedCondition: f.observed_condition, detectedIssue: f.detected_issue,
        remediation: f.remediation,
      })
    }).catch((failure: unknown) => {
      if (controller.signal.aborted) return
      if (failure instanceof AssessmentRequestError && failure.status === 401) reportExpiry()
      setDetailError(failure instanceof AssessmentRequestError && failure.status === 404
        ? 'Finding unavailable for this assessment.' : 'Unable to load finding details. Please retry.')
    }).finally(() => { if (!controller.signal.aborted) setDetailLoading(false) })
    return () => controller.abort()
  }, [assessmentId, findingId, onExpired, retry, suppliedFindings])

  const filtered = useMemo(() => findings.filter(f =>
    (!search || [f.title, f.affectedTarget].some(v => typeof v === 'string' && v.toLowerCase().includes(search.toLowerCase()))) &&
    (!severity || f.severity === severity) && (!source || f.source === source)), [findings, search, severity, source])
  const selected = suppliedFindings !== undefined ? findings.find(f => f.id === findingId) : findingDetail
  const sources = [...new Set(findings.map(f => f.source).filter((value): value is string => typeof value === 'string'))]
  const inReview = assessment?.status === 'Finding Review'
  const quickActions = [
    { action: 'explain_finding', label: 'Explain this finding' },
    { action: 'explain_impact', label: 'Explain the potential impact' },
    { action: 'suggest_fix', label: 'Suggest a fix' },
    { action: 'write_description', label: 'Help write the description' },
    { action: 'explain_tool_output', label: 'Explain the tool output' },
  ] as const

  async function loadAIHistory(offset = 0) {
    if (!findingId) return

    historyRequest.current?.abort()
    const controller = new AbortController()
    historyRequest.current = controller

    setHistoryLoading(true)
    setHistoryError(false)

    try {
      const result = await getFindingAIHistory(
        assessmentId, findingId, controller.signal, 20, offset,
      )

      if (controller.signal.aborted) return

      setAIHistory(previous => {
        if (offset === 0) return result.entries
        const ids = new Set(previous.map(item => item.id))
        return [...previous, ...result.entries.filter(item => !ids.has(item.id))]
      })

      setHistoryOffset(offset + result.entries.length)
      setHistoryMore(result.has_more)
    } catch (failure) {
      if (controller.signal.aborted) return

      if (failure instanceof AssessmentRequestError && failure.status === 401) {
        if (!expiredReported.current) {
          expiredReported.current = true
          expiryHandler.current()
        }
      } else {
        setHistoryError(true)

        if (failure instanceof AssessmentRequestError &&
            [403, 404].includes(failure.status)) {
          aiRequest.current?.abort()
          aiRequest.current = null
          setAIWorking(false)
          setAIHistory([])
          setSavedAnswer(undefined)
          setAIResponse(undefined)
          setSelectedQuestion('')
          setHistoryMore(false)
        }
      }
    } finally {
      if (historyRequest.current === controller) {
        historyRequest.current = null
        setHistoryLoading(false)
      }
    }
  }

  useEffect(() => {
    if (assistantOpen && findingId) {
      void loadAIHistory()
    }

    return () => {
      const active = aiRequest.current
      const history = historyRequest.current

      aiRequest.current = null
      historyRequest.current = null

      active?.abort()
      history?.abort()
    }
  }, [assistantOpen, assessmentId, findingId])

  function closeAssistant() {
    aiRequest.current?.abort()
    historyRequest.current?.abort()

    aiRequest.current = null
    historyRequest.current = null

    setAssistantOpen(false)
    setAIWorking(false)
    setAIResponse(undefined)
    setSavedAnswer(undefined)
    setSelectedQuestion('')
    setQuestion('')
    setAIHistory([])
    setHistoryMore(false)
    setHistoryLoading(false)
    setHistoryError(false)
    setHistoryOffset(0)

    lastAIRequest.current = null
  }

  function backToQuestions() {
    if (aiRequest.current) return

    setSelectedQuestion('')
    setAIResponse(undefined)
    setSavedAnswer(undefined)
  }

  async function openQuestion(request: AIRequest, label: string) {
    if (!findingId || aiRequest.current) return

    setSelectedQuestion(label)
    setAIResponse(undefined)
    setSavedAnswer(undefined)

    if (!csrfToken) {
      setAIResponse({
        status: 'unavailable',
        code: 'ai_session_unavailable',
        message: 'AI assistance requires an active authenticated session.',
        retryable: false,
      })
      return
    }

    const controller = new AbortController()

    aiRequest.current = controller
    lastAIRequest.current = request

    setAIWorking(true)

    try {
      const result = await askFindingAI(
        assessmentId, findingId, request, csrfToken, controller.signal,
      )

      if (controller.signal.aborted) return

      setAIResponse(result)

      if (result.status === 'answered') {
        setQuestion('')
        void loadAIHistory()
      }
    } catch (failure) {
      if (controller.signal.aborted) return

      if (failure instanceof AssessmentRequestError && failure.status === 401) {
        reportExpiry()
        return
      }

      const denied = failure instanceof AssessmentRequestError &&
        [403, 404].includes(failure.status)

      if (denied) {
        historyRequest.current?.abort()
        historyRequest.current = null
        setHistoryLoading(false)
        setAIHistory([])
        setHistoryMore(false)
      }

      setAIResponse({
        status: 'unavailable',
        code: denied ? 'ai_access_unavailable' : 'ai_request_unavailable',
        message: denied
          ? 'AI assistance is unavailable for this finding.'
          : 'The request outcome could not be confirmed. Check earlier questions before trying again.',
        retryable: false,
      })

      if (!denied) void loadAIHistory()
    } finally {
      if (aiRequest.current === controller) {
        aiRequest.current = null
        setAIWorking(false)
      }
    }
  }

  const assistantPanelRef = useRef<HTMLElement | null>(null)

  useEffect(() => {
    if (!assistantOpen) return

    const panel = assistantPanelRef.current
    if (!panel) return

    const previousFocus = document.activeElement
    const closeButton = panel.querySelector<HTMLElement>(
      'button[aria-label="Close AI Assistant"]'
    )

    closeButton?.focus()

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        event.preventDefault()
        closeAssistant()
        return
      }

      if (event.key !== 'Tab' || !panel) return

      const focusable = Array.from(
        panel.querySelectorAll<HTMLElement>(
          'button:not([disabled]), input:not([disabled]), ' +
          'textarea:not([disabled]), select:not([disabled]), ' +
          'a[href], summary, [tabindex="0"]'
        )
      ).filter(element =>
        element.getClientRects().length > 0 &&
        !element.closest('details:not([open]) > :not(summary)')
      )

      if (!focusable.length) {
        event.preventDefault()
        panel.focus()
        return
      }

      const first = focusable[0]
      const last = focusable[focusable.length - 1]
      const active = document.activeElement

      if (event.shiftKey &&
          (active === first || !panel.contains(active))) {
        event.preventDefault()
        last.focus()
      } else if (!event.shiftKey &&
          (active === last || !panel.contains(active))) {
        event.preventDefault()
        first.focus()
      }
    }

    document.addEventListener('keydown', handleKeyDown)

    return () => {
      document.removeEventListener('keydown', handleKeyDown)

      if (previousFocus instanceof HTMLElement &&
          previousFocus.isConnected) {
        previousFocus.focus()
      }
    }
  }, [assistantOpen])

  const displayedAnswer = savedAnswer ??
    (aiResponse?.status === 'answered' ? aiResponse : undefined)
  const goBack = () => { closeAssistant(); onBack?.() }

  if (error) return <section className="analyst-card" role="alert"><p>{error}</p>
    <button type="button" onClick={() => setRetry(n => n + 1)}>Retry</button></section>
  if (!assessment) return <p role="status">Loading assessment…</p>

  if (findingId) return <div className="findings-detail">

    <button type="button" className="findings-text-button" onClick={goBack}>← Back to Findings</button>
    {detailLoading ? <p role="status">Loading finding details…</p> : detailError ? <section className="analyst-card" role="alert"><p>{detailError}</p><button type="button" onClick={() => setRetry(n => n + 1)}>Retry</button></section> : !selected ? <section className="analyst-card" role="alert">
      <h1>Finding unavailable</h1><p>This finding could not be verified for the assessment.</p></section> : <>
      <header className="findings-detail-heading"><h1>{selected.title}</h1><span className={`findings-severity ${selected.severity.toLowerCase()}`}>{selected.severity}</span></header>
      <section className="analyst-card"><h2>Finding Information</h2><dl className="findings-fields three">
        <div><dt>Severity</dt><dd>{selected.severity}</dd></div><div><dt>Detection Source</dt><dd>{selected.source}</dd></div>
        <div><dt>Source Test</dt><dd>{selected.sourceTest}</dd></div></dl></section>
      <div className="findings-two">
        <section className="analyst-card"><h2>Description</h2><p>{selected.description}</p></section>
        <section className="analyst-card"><h2>Potential Impact</h2><p>{selected.impact}</p></section>
      </div>
      <section className="analyst-card"><h2>Technical Details</h2><dl className="findings-fields three">
        <div><dt>Affected Endpoint</dt><dd>{selected.affectedTarget}</dd></div>
        <div><dt>Security Control</dt><dd>{selected.securityControl}</dd></div>
        <div><dt>Observed Condition</dt><dd>{selected.observedCondition}</dd></div></dl></section>
      <section className="analyst-card"><h2>Supporting Evidence</h2>
        <dl className="findings-fields evidence"><div><dt>Detected Issue</dt><dd><strong>{selected.detectedIssue}</strong></dd></div>
          <div><dt>Detection Source</dt><dd><strong>{selected.source}</strong><p>{selected.sourceTest}</p></dd></div></dl>
        <details className="findings-tool-output"><summary>Original Tool Output</summary>
          {selected.originalToolOutput ? <pre>{selected.originalToolOutput}</pre> : <p>Original tool output is not attached to this finding.</p>}
        </details></section>
      <section className="analyst-card"><h2>Remediation</h2><p>{selected.remediation}</p></section>
      <section className="analyst-card"><h2>AI Assistance</h2><button type="button" className="analyst-create" onClick={() => setAssistantOpen(true)}>Ask AI About This Finding</button></section>
      {assistantOpen && <div className="findings-overlay" onClick={closeAssistant}>
        <aside ref={assistantPanelRef} tabIndex={-1} className="findings-assistant" role="dialog" aria-modal="true" aria-label="AI Assistant" onClick={event => event.stopPropagation()}>
          <header><h2>AI Assistant</h2><button type="button" aria-label="Close AI Assistant" onClick={closeAssistant}>×</button></header>
          <div className="findings-assistant-body">
            <div className="findings-assistant-context"><small>About this finding</small><strong>{selected.title}</strong>
              <p><span className={`findings-severity ${selected.severity.toLowerCase()}`}>{selected.severity}</span> {selected.affectedTarget} · {selected.source}</p></div>
            <div className="findings-assistant-note"><strong>AI-generated advice</strong><p>It uses only this finding and its evidence. It never changes the finding or the tool results. Review the advice before you act on it.</p></div>
            {selectedQuestion && (
              <p className="findings-assistant-query">
                {selectedQuestion}
              </p>
            )}

            {aiWorking && (
              <section className="findings-assistant-response" role="status">
                <div className="findings-ai-working">
                  <span className="findings-ai-spinner" aria-hidden="true" />
                  <strong>Reading the finding and its evidence…</strong>
                </div>
                <p>Preparing an answer based on the available evidence.</p>
              </section>
            )}

            {displayedAnswer && (
              <section className="findings-assistant-response">
                <h3>AI Answer</h3>

                <p className="findings-ai-answer">
                  {displayedAnswer.answer}
                </p>

                <div className="findings-ai-evidence">
                  <h3>Evidence used</h3>

                  {displayedAnswer.evidence.map(item => (
                    <details key={item.observation_id}>
                      <summary>
                        {item.source} — Supporting observation
                      </summary>
                      <p>Observation: {item.observation_id}</p>
                      <p>Evidence reference: {item.evidence_id}</p>
                    </details>
                  ))}
                </div>

                {displayedAnswer.limitations.length > 0 && (
                  <details className="findings-ai-limitations">
                    <summary>Limitations</summary>
                    <ul>
                      {displayedAnswer.limitations.map((item, index) => (
                        <li key={index}>{item}</li>
                      ))}
                    </ul>
                  </details>
                )}

                <button type="button" onClick={backToQuestions}>
                  Back to Questions
                </button>
              </section>
            )}

            {aiResponse?.status === 'insufficient_evidence' && (
              <section
                className="findings-assistant-response findings-ai-warning"
                role="status">
                <h3>Not enough evidence</h3>
                <p>{aiResponse.message}</p>

                <button type="button" onClick={backToQuestions}>
                  Back to Questions
                </button>
              </section>
            )}

            {aiResponse?.status === 'unavailable' && (
              <section
                className="findings-assistant-response findings-ai-warning"
                role="status">
                <h3>AI Assistant is unavailable</h3>
                <p>{aiResponse.message}</p>

                {aiResponse.retryable && (
                  <button type="button" onClick={() => {
                    if (lastAIRequest.current) {
                      void openQuestion(
                        lastAIRequest.current,
                        selectedQuestion
                      )
                    }
                  }}>
                    Try Again
                  </button>
                )}

                <button type="button" onClick={backToQuestions}>
                  Back to Questions
                </button>
              </section>
            )}

            {!selectedQuestion && (
              <>
                <h3>What would you like to do?</h3>

                {quickActions.map(item => (
                  <button
                    type="button"
                    className="findings-question"
                    key={item.action}
                    disabled={aiWorking}
                    onClick={() => void openQuestion(
                      { action: item.action },
                      item.label
                    )}>
                    {item.label}
                    <span aria-hidden="true">›</span>
                  </button>
                ))}
              </>
            )}

            <form onSubmit={event => {
              event.preventDefault()
              const value = question.trim()

              if (value && value.length <= 500 && !aiWorking) {
                void openQuestion(
                  { action: 'custom', question: value },
                  value
                )
              }
            }}>
              <label htmlFor="finding-question">
                {displayedAnswer
                  ? 'Ask another question'
                  : 'Or ask your own question'}
              </label>

              <div className="findings-ask">
                <input
                  id="finding-question"
                  value={question}
                  maxLength={500}
                  disabled={aiWorking}
                  onChange={event => setQuestion(event.target.value)}
                  placeholder="Ask about this finding…" />

                <button
                  type="submit"
                  disabled={!question.trim() || aiWorking}>
                  Ask
                </button>
              </div>
            </form>

            {!selectedQuestion && (
              <div className="findings-earlier">
                <strong>Earlier questions</strong>

                {historyLoading && (
                  <p role="status">Loading earlier questions…</p>
                )}

                {historyError && (
                  <>
                    <p>Unable to load earlier questions.</p>
                    <button
                      type="button"
                      onClick={() => void loadAIHistory()}>
                      Retry
                    </button>
                  </>
                )}

                {!historyLoading &&
                  !historyError &&
                  aiHistory.length === 0 && (
                    <p>No questions have been asked about this finding yet.</p>
                )}

                {aiHistory.map(entry => (
                  <button
                    type="button"
                    className="findings-ai-history-item"
                    key={entry.id}
                    onClick={() => {
                      if (aiRequest.current) return

                      setAIResponse(undefined)
                      setSavedAnswer(entry)
                      setSelectedQuestion(entry.question)
                    }}>
                    <span>{entry.question}</span>
                    <small>
                      {new Date(entry.created_at).toLocaleString()}
                    </small>
                  </button>
                ))}

                {historyMore &&
                  !historyLoading &&
                  !historyError &&
                  historyOffset <= 10000 && (
                    <button
                      type="button"
                      onClick={() => void loadAIHistory(historyOffset)}>
                      Load more
                    </button>
                )}
              </div>
            )}
          </div></aside></div>}
    </>}
  </div>

  return <div className="findings-page">
    <nav className="findings-breadcrumb" aria-label="Breadcrumb">Findings</nav>
    <header className="findings-heading"><div><h1>Findings</h1>
      <p>Explore consolidated security findings, inspect supporting evidence, and prepare findings for reporting.</p></div>
      <button type="button" className="analyst-create" onClick={() => setManualOpen(true)}>+ Add Manual Finding</button></header>
    {!inReview && <p className="findings-lifecycle" role="status">This assessment has not yet reached Finding Review. Current status: {assessment.status}.</p>}
    {findingsLoading ? <p role="status">Loading verified findings…</p> : findingsError ? <section className="analyst-card" role="alert"><p>{findingsError}</p><button type="button" onClick={() => setRetry(n => n + 1)}>Retry</button></section> : <><div className="findings-metrics">{(['Total Findings', ...levels] as const).map(label => {
      const count = label === 'Total Findings' ? findings.length : findings.filter(f => f.severity === label).length
      return <section className="analyst-card" key={label}><span>{label}</span><strong>{count}</strong>
        <small>{label === 'Total Findings' ? 'All consolidated findings' : `${label}-severity findings`}</small></section>
    })}</div>
    <section className="analyst-card findings-list" aria-label="Security Findings">
      <h2>Security Findings</h2>
      <p>{findings.length ? 'Consolidated findings generated from completed security tests, with traceability to their original sources.'
        : 'Security findings detected or recorded during this assessment will appear here.'}</p>
      {findings.length ? <>
        <div className="findings-filters"><label><span className="sr-only">Search findings</span>
          <input value={search} onChange={event => setSearch(event.target.value)} placeholder="Search by finding title or affected target" /></label>
          <label><span className="sr-only">Severity</span><select value={severity} onChange={event => setSeverity(event.target.value)}>
            <option value="">Severity</option>{levels.map(level => <option key={level}>{level}</option>)}</select></label>
          <label><span className="sr-only">Source</span><select value={source} onChange={event => setSource(event.target.value)}>
            <option value="">Source</option>{sources.map(item => <option key={item}>{item}</option>)}</select></label></div>
        <div className="findings-table-scroll"><table><thead><tr><th>Finding</th><th>Affected Target</th><th>Severity</th><th>Source</th><th>Action</th></tr></thead>
          <tbody>{filtered.map(f => <tr key={f.id}><td><strong>{f.title}</strong></td><td>{f.affectedTarget}</td>
            <td>{f.severity}</td><td>{f.source}</td><td><button type="button" className="findings-text-button" disabled={!onFinding} onClick={() => onFinding?.(f.id)}>View Details</button></td></tr>)}</tbody></table></div>
        {filtered.length === 0 && <p role="status">No findings match your filters.</p>}
        <footer className="findings-list-footer"><span>Showing {filtered.length} of {findings.length} findings</span>
          <button type="button" disabled title="Report integration is not available yet">Go to Report →</button></footer>
      </> : <div className="findings-empty"><div className="findings-empty-icon" aria-hidden="true">◇</div>
        <h3>No findings yet</h3><p>Findings from security tests will appear here once available. You can also add a finding manually.</p>
        <small>{inReview ? 'No consolidated security issues were recorded for this assessment.' : 'Run tests from Testing or use Add Manual Finding to record an observation.'}</small>
        {!inReview && <button type="button" className="findings-text-button" onClick={onTesting}>Go to Testing</button>}</div>}
    </section>
    </>}
    {manualOpen && <div className="findings-overlay" onClick={() => setManualOpen(false)}><section role="dialog" aria-modal="true" aria-label="Add Manual Finding" className="findings-manual-dialog" onClick={event => event.stopPropagation()}>
      <h2>Add Manual Finding</h2><p>Manual finding creation is not connected to the backend yet. No finding will be saved or added to the consolidated list.</p>
      <button type="button" onClick={() => setManualOpen(false)}>Close</button></section></div>}
  </div>
}
