import TestingCompletion from './TestingCompletion'
import { decideRecommendation } from '../services/testingCompletion'
import type { CompletionOperation } from './TestingCompletion'
import clock from '../assets/testing/Clock.svg'
import { useCallback, useEffect, useRef, useState } from 'react'
import { AssessmentStartError } from '../services/assessmentStart'
import { getExecutionDetails, getTesting, getRecommendations, getRecommendationCheck } from '../services/testing'
import type { ExecutionDetails, TestingData, Recommendation, RecommendationData } from '../services/testing'
import plus from '../assets/testing/Plus.svg'
import information from '../assets/testing/Information.svg'
import marker from '../assets/testing/Marker.svg'
import './TestingPage.css'

function timestamp(value: string | null) {
  if (!value) return 'Not recorded'
  const date = new Date(value)
  return Number.isNaN(date.valueOf()) ? 'Not recorded' : date.toLocaleString()
}

function StatusMessage({ data }: { data: TestingData }) {
  const c = data.counts
  return <p>{c.queued > 0 && `${c.queued} ${c.queued === 1 ? 'test is' : 'tests are'} queued; queued tests are not running. `}
    {c.in_progress > 0 && `${c.in_progress} ${c.in_progress === 1 ? 'test is' : 'tests are'} in progress. `}
    {c.completed > 0 && `${c.completed} completed. `}{c.failed > 0 && `${c.failed} failed. `}
    {c.blocked > 0 && `${c.blocked} blocked. `}{c.stopped > 0 && `${c.stopped} stopped. `}
    {c.cancelled > 0 && `${c.cancelled} cancelled. `}Select View Details to review the latest available execution information.</p>
}

function Details({ assessmentId, executionId, onClose, onExpired }: {
  assessmentId: string; executionId: string; onClose: () => void; onExpired: () => void
}) {
  const [data, setData] = useState<ExecutionDetails>()
  const [error, setError] = useState('')
  const [retry, setRetry] = useState(0)
  const dialog = useRef<HTMLDialogElement>(null)
  useEffect(() => {
    dialog.current?.showModal()
    const controller = new AbortController()
    void getExecutionDetails(assessmentId, executionId, controller.signal).then(result => {
      if (!controller.signal.aborted) setData(result)
    }).catch((failure: unknown) => {
      if (controller.signal.aborted) return
      if (failure instanceof AssessmentStartError && failure.status === 401) onExpired()
      else setError(failure instanceof AssessmentStartError && [403, 404].includes(failure.status)
        ? 'Execution unavailable.' : 'Unable to load execution details.')
    })
    return () => controller.abort()
  }, [assessmentId, executionId, onExpired, retry])

  const lastAttempt = data?.attempts.at(-1)
  const isRunning = data?.status === 'Running'
  const isFailed = data?.status === 'Failed'
  const isCompleted = data?.status === 'Completed'
  const stateTitle = isRunning ? 'Running Test Details' : isFailed ? 'Failed Test Details'
    : isCompleted ? 'Completed Test Details' : 'Execution Details'
  const totalObservations = data?.processing.reduce((sum, item) => sum + item.observation_count, 0) ?? 0

  return <dialog className="testing-details analyst-card" ref={dialog} aria-labelledby="execution-details-title" onCancel={onClose}>
    <div className="testing-details-heading">
      <h2 id="execution-details-title">{stateTitle}</h2>
      <button type="button" className="analyst-link" onClick={onClose}>Close</button>
    </div>
    {error ? <div role="alert"><p>{error}</p><button type="button" className="analyst-link" onClick={() => { setError(''); setRetry(n => n + 1) }}>Retry</button></div>
      : !data ? <p role="status">Loading execution details…</p> : <>
        <div className="testing-detail-summary">
          <div><h3>{data.test_name}</h3><p>{data.tool} · {data.target}</p></div>
          <span className="testing-state" data-status={data.status}>{data.status}</span>
        </div>
        <p className="testing-detail-status" role="status">
          {isCompleted ? 'The test completed. Review the persisted results and evidence below.'
            : isRunning ? 'This test is in progress. Results may not be available until processing completes.'
            : isFailed ? 'This test failed. Review the recorded reason and any partial evidence.'
            : data.status === 'Queued' ? 'This test is queued and has not started.'
            : `Execution status: ${data.status}. Review the recorded information below.`}
        </p>
        <section className="testing-detail-section" aria-label="Execution overview">
          <h3>Execution Overview</h3>
          <dl className="testing-detail-grid">
            <div><dt>Test</dt><dd>{data.test_name}</dd></div>
            <div><dt>Tool</dt><dd>{data.tool}</dd></div>
            <div><dt>Target</dt><dd>{data.target}</dd></div>
            <div><dt>Status</dt><dd>{data.status}</dd></div>
            <div><dt>Started</dt><dd>{timestamp(lastAttempt?.started_at ?? null)}</dd></div>
            <div><dt>Finished</dt><dd>{timestamp(lastAttempt?.finished_at ?? null)}</dd></div>
          </dl>
        </section>
        {isFailed && <section className="testing-detail-section" aria-label="Failure information">
          <h3>Failure Information</h3>
          <dl className="testing-metadata">
            <div><dt>Reason code</dt><dd>{lastAttempt?.reason_code ?? 'Not recorded'}</dd></div>
            <div><dt>Exit code</dt><dd>{lastAttempt?.exit_code ?? 'Not recorded'}</dd></div>
            <div><dt>Recovery status</dt><dd>{lastAttempt?.recovery_reason ?? 'Not recorded'}</dd></div>
          </dl>
        </section>}
        <section className="testing-detail-section" aria-label="Test results">
          <h3>{isRunning ? 'Progress & Results' : 'Test Results'}</h3>
          <div className="testing-result-metrics">
            <div><strong>{totalObservations}</strong><span>Processed observations</span></div>
            <div><strong>{data.evidence.length}</strong><span>Evidence records</span></div>
            <div><strong>{data.processing.length}</strong><span>Processing runs</span></div>
          </div>
          {data.observations.length ? <ul className="testing-detail-list">{data.observations.map(item =>
            <li key={item.id}>{item.type}{item.partial ? ' · Partial result' : ''}</li>)}</ul>
            : <p>No processed observations recorded.</p>}
        </section>
        <section className="testing-detail-section" aria-label="Evidence summaries">
          <h3>Supporting Evidence</h3>
          {data.evidence.length ? <ul className="testing-detail-list">{data.evidence.map(item =>
            <li key={item.id}>{item.format} · {item.size_bytes} bytes{item.partial ? ' · Partial' : ''} · {timestamp(item.collected_at)}</li>)}</ul>
            : <p>No scanner evidence recorded.</p>}
        </section>
        <details className="testing-detail-section" open>
          <summary>Technical Details</summary>
          <dl className="testing-metadata">
            <div><dt>Execution ID</dt><dd>{data.id}</dd></div>
            <div><dt>Tool</dt><dd>{data.tool}</dd></div>
            <div><dt>Target</dt><dd>{data.target}</dd></div>
            <div><dt>Profile</dt><dd>{data.profile_id} v{data.profile_version}</dd></div>
            <div><dt>Dispatch status</dt><dd>{data.dispatch_status}</dd></div>
          </dl>
          <h3>Execution attempts</h3>
          {!data.attempts.length ? <p>No execution attempt recorded. Queued does not mean Running.</p>
            : data.attempts.map(attempt => <p key={attempt.id}>Attempt {attempt.attempt_number}: {attempt.status}
              {' · Started: '}{timestamp(attempt.started_at)}{' · Finished: '}{timestamp(attempt.finished_at)}
              {attempt.reason_code && ` · ${attempt.reason_code}`}
              {attempt.recovery_reason && ` · ${attempt.recovery_reason}`}</p>)}
          <h3>Result processing</h3>
          {!data.processing.length ? <p>No processing outcome recorded.</p> : data.processing.map(item =>
            <p key={item.id}>{item.status} · {item.observation_count} observations
              {item.partial && ' · Partial'}{item.error_code && ` · ${item.error_code}`}</p>)}
          <h3>Execution timeline</h3>
          {data.events.length ? <ul className="testing-detail-list">{data.events.map(item =>
            <li key={item.id}>{eventLabel(item.event)} · {timestamp(item.occurred_at)}</li>)}</ul>
            : <p>No execution events recorded.</p>}
        </details>
        <p className="testing-secondary">Read-only execution information. This view does not authorize scanner execution or expose original tool output.</p>
      </>}
  </dialog>
}

const eventNames: Record<string, string> = {
  execution_queued: 'Queued', execution_claimed: 'Execution claimed',
  scanner_started: 'Scanner started', evidence_persisted: 'Evidence saved',
  execution_finished: 'Execution finished', dispatch_blocked: 'Dispatch blocked',
  recovery_required: 'Recovery required',
}
function eventLabel(event: string) {
  return eventNames[event] ?? event.replace(/_/g, ' ')
}

function SuggestionFields({ recommendation }: { recommendation: Recommendation }) {
  return <dl className="testing-review-fields testing-three-fields">
    <div><dt>Target</dt><dd>{recommendation.target}</dd></div>
    <div><dt>Service</dt><dd>{recommendation.service ?? 'Not identified'}</dd></div>
    <div><dt>Port</dt><dd>{recommendation.port ?? 'Not identified'}</dd></div>
  </dl>
}

function AlternativeReview({ assessmentId, recommendation, onExpired }: {
  assessmentId: string; recommendation: Recommendation; onExpired: () => void
}) {
  const [state, setState] = useState<'checking' | 'unavailable' | 'error'>('checking')
  const [reason, setReason] = useState('')
  const [retry, setRetry] = useState(0)
  useEffect(() => {
    const controller = new AbortController()
    void Promise.all([
      getRecommendationCheck(assessmentId, recommendation.id, 'eligibility', controller.signal),
      getRecommendationCheck(assessmentId, recommendation.id, 'authorization-review', controller.signal),
    ]).then(([, review]) => {
      if (controller.signal.aborted) return
      setReason(review.reason_code)
      setState('unavailable')
    }).catch((failure: unknown) => {
      if (controller.signal.aborted) return
      setState('error')
      if (failure instanceof AssessmentStartError && failure.status === 401) onExpired()
    })
    return () => controller.abort()
  }, [assessmentId, recommendation.id, onExpired, retry])
  const explanation = reason === 'tool_integration_pending' ? 'The proposed tool integration is pending; no executable alternative is available.'
    : reason === 'followup_profile_not_supported'
    ? 'No supported follow-up test profile is available for this recommendation.'
    : reason === 'assessment_not_testing' ? 'This assessment is no longer in Testing.'
    : ['target_scope_stale', 'target_out_of_scope', 'observation_target_mismatch', 'target_unavailable'].includes(reason)
      ? 'The target or its authorized scope could not be verified for an alternative test.'
      : 'No authorized alternative is currently available.'
  return <>
    <section className="testing-alternative-current" aria-label="Current Recommendation"><h3>Current Recommendation</h3>
      <div className="testing-inset"><p className="testing-field-label">Test</p><h4>{recommendation.title}</h4>
        <p className="testing-field-label">Tool</p><p>{recommendation.suggested_tool ?? 'Not available'}</p><SuggestionFields recommendation={recommendation} /></div>
    </section>
    <section aria-label="Select Alternative"><h3>Select Alternative</h3>
      <p>Choose an integrated security tool and one of its configured test profiles.</p>
      <label className="testing-alternative-field" htmlFor="alternative-tool">Security Tool</label>
      <select id="alternative-tool" disabled value=""><option value="">No verified tools available for this recommendation</option></select>
      <label className="testing-alternative-field" htmlFor="alternative-profile">Test Profile</label>
      <select id="alternative-profile" disabled value=""><option value="">No eligible test profiles available</option></select>
    </section>
    <section aria-label="Selected Test"><h3>Selected Test</h3><div className="testing-inset"><h4>No alternative selected</h4>
      <p>Select a security tool and test profile to review the alternative.</p><p>Target: {recommendation.target}</p></div></section>
    <section aria-label="Compatibility Status"><h3>Compatibility Status</h3>
      <div className="testing-review-safety" role="status"><h4>{state === 'checking' ? 'Checking' : 'Unavailable'}</h4>
        <p>{state === 'checking' ? 'Checking available profiles and current authorization constraints.'
          : state === 'error' ? 'Unable to verify alternatives. No test can be confirmed.' : explanation}</p>
        {state === 'error' && <button type="button" className="analyst-link" onClick={() => { setState('checking'); setRetry(n => n + 1) }}>Retry alternatives</button>}
      </div>
    </section>
  </>
}

function RecommendationReview({ assessmentId, recommendation, onClose, onExpired, csrfToken, onChanged }: {
  assessmentId: string; recommendation: Recommendation; onClose: () => void; onExpired: () => void; csrfToken: string; onChanged: () => void
}) {
  const [choosingAlternative, setChoosingAlternative] = useState(false)
  const [saving, setSaving] = useState(false)
  const [decisionError, setDecisionError] = useState('')
  const [uncertain, setUncertain] = useState(false)
  const pending = useRef(false)
  const decisionController = useRef<AbortController | null>(null)
  useEffect(() => () => decisionController.current?.abort(), [])
  async function decide(outcome: 'Accepted' | 'Rejected') {
    if (pending.current || uncertain || !csrfToken) return
    pending.current = true; setSaving(true); setDecisionError('')
    const controller = new AbortController(); decisionController.current = controller
    try {
      await decideRecommendation(assessmentId, recommendation.id, 'Reviewed', csrfToken, controller.signal, outcome)
      const verified = await getRecommendations(assessmentId, controller.signal)
      if (verified.recommendations.find(item => item.id === recommendation.id)?.review_outcome !== outcome) throw new Error('Review not verified')
      if (!controller.signal.aborted) { onChanged(); onClose() }
    } catch (failure) {
      if (controller.signal.aborted) return
      if (failure instanceof AssessmentStartError && failure.status === 401) onExpired()
      const unknown = !(failure instanceof AssessmentStartError) || failure.status >= 500 || [408,429].includes(failure.status)
      setUncertain(unknown)
      setDecisionError(unknown ? 'Review outcome is unverified. Close and refresh recommendations before another decision.' : 'The decision was not saved. Refresh the current assessment before retrying.')
      onChanged()
    } finally { if (!controller.signal.aborted) { pending.current=false;setSaving(false) } }
  }

  const dialog = useRef<HTMLDialogElement>(null)
  const closeButton = useRef<HTMLButtonElement>(null)
  useEffect(() => {
    const trigger = document.activeElement instanceof HTMLElement ? document.activeElement : null
    const element = dialog.current
    element?.showModal()
    closeButton.current?.focus()
    return () => { element?.close(); if (trigger?.isConnected) trigger.focus() }
  }, [])
  return <dialog ref={dialog} className="testing-review-dialog" aria-labelledby="recommendation-review-title"
    onCancel={event => { event.preventDefault(); if (!saving) onClose() }}>
    <header className="testing-review-header"><h2 id="recommendation-review-title">{choosingAlternative ? 'Choose Alternative' : 'Review Recommendation'}</h2>
      <button ref={closeButton} type="button" aria-label="Close recommendation review" disabled={saving} onClick={onClose}>×</button></header>
    <div className="testing-review-body">
      {choosingAlternative ? <AlternativeReview assessmentId={assessmentId} recommendation={recommendation} onExpired={onExpired} /> : <>
        <section aria-label="Selected Suggestion"><h3>{recommendation.title}</h3><span className="testing-recommendation-status">{recommendation.decision === null && <img src={clock} alt="" />}{recommendation.decision === 'Reviewed' ? recommendation.review_outcome ?? 'Reviewed' : recommendation.decision ?? 'Pending Review'}</span></section>
        <section aria-label="Suggestion Information"><h3>Suggestion Information</h3><SuggestionFields recommendation={recommendation} /></section>
        <section><h3>Why Is This Suggested?</h3>{(recommendation.explanation ?? [recommendation.reason]).map((text, index) => <p key={index}>{text}</p>)}</section>
        <section aria-label="Source Test"><h3>Source Test</h3><dl className="testing-review-fields testing-three-fields">
          <div><dt>Test</dt><dd>{recommendation.source_test?.test_name ?? 'Not available'}</dd></div>
          <div><dt>Tool</dt><dd>{recommendation.source_test?.tool ?? 'Not available'}</dd></div>
          <div><dt>Status</dt><dd>{recommendation.source_test
            ? <span className="testing-state testing-status-badge" data-status={recommendation.source_test.status}>{recommendation.source_test.status}</span> : 'Not available'}</dd></div>
        </dl></section>
        <section aria-label="Proposed Test"><h3>Proposed Test</h3>{recommendation.proposed_test ? <>
          <h4>{recommendation.proposed_test.name}</h4><p>Tool: {recommendation.proposed_test.tool}</p>
          <p>{recommendation.proposed_test.description}</p><p role="status">Integration pending — execution unavailable. Acceptance records review only.</p>
        </> : <p>No executable follow-up test is currently supported for this observation.</p>}</section>
      </>}
    </div>
    {decisionError && <p role="alert">{decisionError}</p>}
    <footer className="testing-review-footer">{choosingAlternative ? <>
      <button type="button" onClick={() => setChoosingAlternative(false)}>Cancel</button>
      <button type="button" disabled>Confirm Alternative</button>
    </> : <><button type="button" disabled={saving} onClick={onClose}>Close</button>
      {recommendation.kind === 'evidence_followup' ? <>
        <button type="button" disabled={!csrfToken || saving || uncertain} onClick={() => void decide('Accepted')}>{saving ? 'Saving…' : 'Accept'}</button>
        <button type="button" disabled={!csrfToken || saving || uncertain} onClick={() => void decide('Rejected')}>Reject</button>
      </> : <button type="button" disabled>Start Test</button>}
      <button type="button" disabled={saving} onClick={() => setChoosingAlternative(true)}>Choose Alternative</button></>}
    </footer>
  </dialog>
}

type TestingPageProps = { assessmentId: string; onExpired: () => void; csrfToken?: string }

export default function TestingPage(props: TestingPageProps) {
  return <TestingAssessment key={props.assessmentId} {...props} />
}

function TestingAssessment({ assessmentId, onExpired, csrfToken = '' }: TestingPageProps) {
  const [data, setData] = useState<TestingData>()
  const [error, setError] = useState('')
  const [retry, setRetry] = useState(0)
  const [selected, setSelected] = useState<string>()
  const [activeTab, setActiveTab] = useState<'activity' | 'recommendations' | 'completion'>('activity')
  const detailButton = useRef<HTMLButtonElement | null>(null)
  const [recommendations, setRecommendations] = useState<RecommendationData>()
  const [recommendationError, setRecommendationError] = useState('')
  const [recommendationRetry, setRecommendationRetry] = useState(0)
  const [reviewedRecommendation, setReviewedRecommendation] = useState<string>()
  const recommendationGeneration = useRef(0)
  const [completionOperation, setCompletionOperation] = useState<CompletionOperation>({ phase: 'idle' })

  useEffect(() => {
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout> | undefined
    let forbidden = false
    async function load() {
      try {
        const result = await getTesting(assessmentId, controller.signal)
        if (controller.signal.aborted) return
        setData(result)
        setError('')
      } catch (failure) {
        if (controller.signal.aborted) return
        if (failure instanceof AssessmentStartError && [401, 403, 404].includes(failure.status)) {
          forbidden = true
          setData(undefined)
          setSelected(undefined)
          recommendationGeneration.current += 1
          setRecommendations(undefined)
          setReviewedRecommendation(undefined)
          setError(failure.status === 401 ? 'Your session has ended. Sign in again to continue.' : 'Assessment unavailable.')
          if (failure.status === 401) onExpired()
        } else setError('Unable to refresh Testing. Retry to retrieve the latest status.')
      } finally {
        if (!controller.signal.aborted && !forbidden) timer = setTimeout(() => { void load() }, 5000)
      }
    }
    void load()
    return () => { controller.abort(); clearTimeout(timer) }
  }, [assessmentId, onExpired, retry])

  const hasTestingData = data !== undefined
  const invalidateRecommendations = useCallback(() => {
    recommendationGeneration.current += 1
    setRecommendationError('')
    setRecommendationRetry(n => n + 1)
  }, [])

  useEffect(() => {
    if (!hasTestingData || error || (activeTab !== 'recommendations' && recommendationRetry === 0)) return
    const generation = ++recommendationGeneration.current
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout> | undefined
    let stopped = false
    async function load() {
      try {
        const result = await getRecommendations(assessmentId, controller.signal)
        if (controller.signal.aborted || generation !== recommendationGeneration.current) return
        setRecommendations(result)
        setRecommendationError('')
      } catch (failure) {
        if (controller.signal.aborted || generation !== recommendationGeneration.current) return
        if (failure instanceof AssessmentStartError && [401, 403, 404].includes(failure.status)) {
          stopped = true
          setRecommendations(undefined)
          setRecommendationError(failure.status === 401 ? 'Your session has ended. Sign in again to continue.' : 'Recommendations unavailable.')
          if (failure.status === 401) onExpired()
        } else setRecommendationError('Unable to load recommendations. Retry to retrieve the latest suggestions.')
      } finally {
        if (!controller.signal.aborted && generation === recommendationGeneration.current && !stopped && activeTab === 'recommendations') timer = setTimeout(() => { void load() }, 5000)
      }
    }
    void load()
    return () => { controller.abort(); clearTimeout(timer) }
  }, [activeTab, assessmentId, hasTestingData, error, onExpired, recommendationRetry])

  const empty = data?.counts.total === 0
  const scope = data?.authorization_scope
  return <>
    <nav aria-label="Breadcrumb">Testing</nav>
    <header className="testing-heading"><div><h1>Testing</h1>
      <p>Run security tests, check recommendations, and review your testing progress.</p></div>
      <button type="button" className="analyst-create testing-manual" disabled title="Manual testing is unavailable in this release">
        <img src={plus} alt="" />Run Manual Test</button>
    </header>
    <div className="testing-tabs" role="tablist" aria-label="Testing views">
      <button type="button" role="tab" id="test-activity-tab" aria-selected={activeTab === 'activity'} aria-controls="test-activity-panel" onClick={() => setActiveTab('activity')}>Test Activity</button>
      <button type="button" role="tab" id="recommendations-tab" aria-selected={activeTab === 'recommendations'} aria-controls="recommendations-panel" onClick={() => setActiveTab('recommendations')}>Recommendations <span className="testing-recommendation-count" aria-label={`${recommendations?.count ?? 0} recommendations`}>{recommendations?.count ?? 0}</span></button>
      <button type="button" role="tab" id="testing-completion-tab" aria-selected={activeTab === 'completion'} aria-controls="testing-completion-panel" onClick={() => setActiveTab('completion')}>Testing Completion</button>
    </div>
    {error && <section className="testing-load-error analyst-card" role="alert"><p>{error}</p>
      {data && <p>Displaying the last retrieved data; current status is unverified.</p>}
      <button className="analyst-link" type="button" onClick={() => setRetry(n => n + 1)}>Retry</button></section>}
    {!data && !error && <p role="status">Loading Testing…</p>}
    {data && <div role="tabpanel" id={activeTab === 'activity' ? 'test-activity-panel' : activeTab === 'recommendations' ? 'recommendations-panel' : 'testing-completion-panel'} aria-labelledby={activeTab === 'activity' ? 'test-activity-tab' : activeTab === 'recommendations' ? 'recommendations-tab' : 'testing-completion-tab'} className="testing-panel">
      {activeTab === 'completion' ? <TestingCompletion assessmentId={assessmentId} csrfToken={csrfToken} operation={completionOperation} onOperationChange={setCompletionOperation} onExpired={onExpired} onDecisionsChanged={invalidateRecommendations} onContinue={() => setActiveTab('activity')} onRecommendations={() => setActiveTab('recommendations')} /> : activeTab === 'recommendations' ? <>
        <div className="testing-metrics">{[
          ['Total Tests', data.counts.total], ['In Progress', data.counts.in_progress],
          ['Completed', data.counts.completed], ['Failed', data.counts.failed],
        ].map(([label, value]) => <section className="analyst-card" key={label} aria-label={String(label)}>
          <p>{label}</p><strong>{value}</strong></section>)}</div>
        <section className="testing-notice" aria-label="Current Status"><img src={information} alt="" />
          <div><h2>Current Status</h2>{data.counts.total === 0
            ? <p>No tests have been scheduled. Recommendations will appear when supported results become available.</p>
            : <><p>Recommendations are based on the information currently available.</p><StatusMessage data={data} /></>}</div></section>
        <section className="analyst-card testing-recommendations" aria-label="Recommendations">
          <h2>Recommendations</h2>
          <p>Review recommended testing actions before deciding whether to proceed.</p>
          {recommendationError && <div role="alert"><p>{recommendationError}</p>
            {recommendations && <p>Displayed suggestions are from the last successful read; current decisions are unverified.</p>}
            <button type="button" className="analyst-link" onClick={() => setRecommendationRetry(n => n + 1)}>Retry recommendations</button></div>}
          {!recommendations && !recommendationError && <p role="status">Loading recommendations…</p>}
          {recommendations?.count === 0 && !recommendationError && <div className="testing-recommendations-empty">
            <div className="testing-recommendations-empty-icon" aria-hidden="true">⌕</div>
            <h3>No suggested next steps yet</h3>
            <p>No recommendations are available for this assessment yet. Suggested next steps will appear here when supported analysis is available. Host discovery alone does not identify services or web applications.</p>
          </div>}
          {recommendations && recommendations.count > 0 && <div className="testing-recommendation-list">
            {recommendations.recommendations.map(item => <article className="testing-recommendation-item" key={item.id}>
              <div className="testing-recommendation-title"><h3>{item.title}</h3><span className="testing-recommendation-status">{item.decision === null && <img src={clock} alt="" />}{item.decision === 'Reviewed' ? item.review_outcome ?? 'Reviewed' : item.decision ?? 'Pending Review'}</span></div>
              <SuggestionFields recommendation={item} />
              <p className="testing-recommendation-reason">{item.reason}</p>

              <button type="button" className="analyst-create testing-review-action" onClick={event => { event.currentTarget.focus(); setReviewedRecommendation(item.id) }}>Review Suggestion</button>
            </article>)}
          </div>}
        </section>
      </> : <>
      <div className="testing-metrics">{[
        ['Total Tests', data.counts.total], ['In Progress', data.counts.in_progress],
        ['Completed', data.counts.completed], ['Failed', data.counts.failed],
      ].map(([label, value]) => <section className="analyst-card" key={label} aria-label={String(label)}>
        <p>{label}</p><strong>{value}</strong></section>)}</div>
      {!empty && <section className="testing-notice" aria-label="Current Status"><img src={information} alt="" />
        <div><h2>Current Status</h2><StatusMessage data={data} /></div></section>}
      <section className={'analyst-card testing-activity' + (empty ? ' testing-activity-empty' : '')}>
        <h2>Test Activity</h2><p>{empty ? 'Tests started for this assessment will appear here.' : 'Monitor your tests and review their results.'}</p>
        {empty ? <div className="testing-empty"><div aria-hidden="true">◇</div><h3>No tests have been run yet</h3>
          <p>No baseline executions have been scheduled for this assessment. Test activity and results will appear here.</p>
          <small>Manual testing is not available in this release.</small></div>
          : <><div className="testing-table-scroll"><table aria-label="Test Activity"><thead><tr>
            {['Test', 'Tool', 'Target', 'Status', 'Actions'].map(label => <th scope="col" key={label}>{label}</th>)}
          </tr></thead><tbody>{data.executions.map(execution => <tr key={execution.id}>
            <th scope="row">{execution.test_name}</th><td>{execution.tool}</td><td>{execution.target}</td>
            <td><span className="testing-state" data-status={execution.status}>{execution.status}</span></td>
            <td><button type="button" className="analyst-link" aria-label={'View Details: ' + execution.test_name + ' on ' + execution.target}
              onClick={event => { detailButton.current = event.currentTarget; setSelected(execution.id) }}>View Details</button></td>
          </tr>)}</tbody></table></div><small>Additional tests will appear here as they are scheduled.</small></>}
      </section>
      {!empty && <>
        <section className="testing-notice"><img src={information} alt="" /><div><h2>View Test Results</h2>
          <p>Select View Details to review recorded execution attempts, processing outcomes and evidence summaries.</p></div></section>
        <div className="testing-context">
          <section className="analyst-card"><h2>Authorization &amp; Scope</h2><p>What this assessment is allowed to test.</p>
            <dl className="testing-metadata">
              <div><dt>Authorized scope</dt><dd>{scope?.scope_revision != null ? `Revision ${scope.scope_revision}` : 'Not recorded'}<small>Scope boundaries are not provided by the Testing API.</small></dd></div>
              <div><dt>Targets under test</dt><dd>{[...new Set(data.executions.map(row => row.target))].join(', ')}</dd></div>
              <div><dt>Baseline</dt><dd>{[...new Set(data.executions.map(row => `${row.test_name} v${row.profile_version}`))].join(', ')}</dd></div>
              <div><dt>Automation policy</dt><dd>{scope?.policy?.id ? `${scope.policy.id} v${scope.policy.version ?? '—'}` : 'Not provided'}</dd></div>
              <div><dt>Authorization mode</dt><dd>{scope?.mode ?? 'Not recorded'}</dd></div>
              <div><dt>Excluded targets</dt><dd>{scope?.excluded_targets.length ?? 0}</dd></div>
              <div><dt>Excluded activities</dt><dd>{scope?.excluded_activities.length ?? 0}</dd></div>
              <div><dt>Authorized by</dt><dd>Not provided by the Testing API.</dd></div>
            </dl></section>
          <section className="analyst-card"><h2>Discovered So Far</h2><p>Discovery and security-test results.</p>
            <div className="testing-discoveries">{['Open ports', 'Services', 'Web target'].map(label => <div key={label}><strong>—</strong><small>{label}</small></div>)}</div>
            <p>Port, service and web-target totals are not provided by this API. Recorded host discovery observations are listed below.</p>
            <p>{data.discovered_so_far.filter(item => item.type === 'host_discovery' && item.data?.status === 'up').length} responding host observations · {data.discovered_so_far.filter(item => item.partial).length} partial observations</p>
            {data.discovered_so_far.length ? <ul>{data.discovered_so_far.map(item => <li key={item.id}>
              {item.type === 'host_discovery' && typeof item.data?.address === 'string' && typeof item.data?.status === 'string'
                ? `${item.data.address}: ${item.data.status}` : item.type}{item.partial && ' (partial)'}</li>)}</ul> : <p>No discovery observations recorded.</p>}
          </section>
          <section className="analyst-card"><h2>Recent Activity</h2><p>Latest testing events.</p>
            {data.recent_activity.length ? <ul className="testing-events">{data.recent_activity.map((item, index) => {
              const execution = data.executions.find(row => row.id === item.execution_id)
              return <li key={item.execution_id + ':' + index}><img src={marker} alt="" /><div>
                <span>{`${execution?.test_name ?? 'Execution'}: ${eventLabel(item.event)}`}</span>
                <small><time dateTime={item.occurred_at}>{timestamp(item.occurred_at)}</time></small></div></li>
            })}</ul> : <p>No testing events recorded.</p>}
            <button type="button" className="analyst-link" disabled title="Audit Log is unavailable in this release">View Audit Log</button>
          </section>
        </div>
      </>}
      </>}
    </div>}
    {reviewedRecommendation && recommendations?.recommendations.some(item => item.id === reviewedRecommendation) && <RecommendationReview assessmentId={assessmentId} onExpired={onExpired} csrfToken={csrfToken} onChanged={invalidateRecommendations}
      recommendation={recommendations.recommendations.find(item => item.id === reviewedRecommendation)!}
      onClose={() => setReviewedRecommendation(undefined)} />}
    {selected && <Details key={assessmentId + ':' + selected} assessmentId={assessmentId} executionId={selected} onExpired={onExpired}
      onClose={() => { setSelected(undefined); detailButton.current?.focus() }} />}
  </>
}
