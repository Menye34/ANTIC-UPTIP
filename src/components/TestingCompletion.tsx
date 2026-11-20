import { useEffect, useRef, useState } from 'react'
import { AssessmentStartError } from '../services/assessmentStart'
import { completeTesting, CompletionOutcomeUncertainError, decideRecommendation, getCompletionReview } from '../services/testingCompletion'
import type { CompletionReview as CompletionData } from '../services/testingCompletion'
import information from '../assets/testing/Information.svg'

export type CompletionOperation = { phase: 'idle' | 'submitting' | 'uncertain' }
  | { phase: 'confirmed'; review: CompletionData }
type Props = {
  assessmentId: string
  csrfToken: string
  operation: CompletionOperation
  onOperationChange: (next: CompletionOperation) => void
  onContinue: () => void
  onFindings: () => void
  currentAnalyst?: { id: string; username: string }
  onRecommendations: () => void
  onExpired: () => void
  onDecisionsChanged: () => void
}

export default function TestingCompletion(props: Props) {
  return <CompletionContent key={props.assessmentId} {...props} />
}

function CompletionContent({ assessmentId, csrfToken, operation, onOperationChange, onContinue, onFindings, currentAnalyst, onRecommendations, onExpired, onDecisionsChanged }: Props) {
  const [review, setReview] = useState<CompletionData | undefined>(() => operation.phase === 'confirmed' ? operation.review : undefined)
  const [error, setError] = useState('')
  const [retry, setRetry] = useState(0)
  const [confirmation, setConfirmation] = useState<CompletionData>()
  const [submitting, setSubmitting] = useState(false)
  const dialog = useRef<HTMLDialogElement>(null)
  const completeButton = useRef<HTMLButtonElement>(null)
  const reviewPanel = useRef<HTMLElement>(null)
  const wasOpen = useRef(false)
  const captured = useRef<CompletionData | undefined>(undefined)
  const inFlight = useRef(false)
  const mounted = useRef(false)
  const readGeneration = useRef(0)
  const mutation = useRef<AbortController | undefined>(undefined)
  const latestOperation = useRef(operation)
  useEffect(() => { latestOperation.current = operation }, [operation])

  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
      readGeneration.current += 1
      // A cancelled POST may already have committed. Keep the parent lock
      // across tab remounts until an authorized read establishes completion.
      if (latestOperation.current.phase === 'submitting') {
        latestOperation.current = { phase: 'uncertain' }
        onOperationChange({ phase: 'uncertain' })
      }
      mutation.current?.abort()
    }
  }, [onOperationChange])

  useEffect(() => {
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout> | undefined
    let stopped = false
    async function refresh() {
      const generation = ++readGeneration.current
      try {
        if (inFlight.current) return
        const next = await getCompletionReview(assessmentId, controller.signal)
        if (controller.signal.aborted || !mounted.current || generation !== readGeneration.current) return
        if (latestOperation.current.phase === 'confirmed') {
          // Never regress a receipt-backed success to a polled Testing response.
          setReview(latestOperation.current.review)
          setError(next.lifecycle_status === 'Finding Review' && next.completion ? ''
            : 'The latest refresh did not match confirmed completion. The persisted completion receipt is retained.')
          return
        }
        setReview(next)
        setError('')
        if (next.lifecycle_status === 'Finding Review' && next.completion) {
          captured.current = undefined
          setConfirmation(undefined)
          latestOperation.current = { phase: 'confirmed', review: next }
          onOperationChange(latestOperation.current)
        } else if (captured.current && (captured.current.snapshot_digest !== next.snapshot_digest
          || captured.current.snapshot_schema_version !== next.snapshot_schema_version || !next.ready || !next.can_complete)) {
          captured.current = undefined
          setConfirmation(undefined)
          setError('The assessment changed. Review the latest snapshot and confirm again.')
        }
      } catch (failure) {
        if (controller.signal.aborted || !mounted.current || generation !== readGeneration.current) return
        captured.current = undefined
        setConfirmation(undefined)
        const denied = failure instanceof AssessmentStartError && [401, 403, 404].includes(failure.status)
        if (latestOperation.current.phase !== 'confirmed' || denied) setReview(undefined)
        setError('Unable to verify completion readiness. Retry to retrieve the latest status.')
        if (denied) {
          // Do not retain protected receipt details after access is withdrawn.
          if (latestOperation.current.phase === 'confirmed') {
            latestOperation.current = { phase: 'uncertain' }
            onOperationChange(latestOperation.current)
          }
          stopped = true
          if (failure.status === 401) onExpired()
        }
      } finally {
        if (!controller.signal.aborted && !stopped) timer = setTimeout(() => { void refresh() }, 5000)
      }
    }
    void refresh()
    return () => { controller.abort(); clearTimeout(timer); readGeneration.current += 1 }
  }, [assessmentId, onExpired, onOperationChange, retry])

  useEffect(() => {
    if (confirmation && !dialog.current?.open) {
      dialog.current?.showModal()
      wasOpen.current = true
    } else if (!confirmation && wasOpen.current) {
      dialog.current?.close()
      wasOpen.current = false
      if (completeButton.current && !completeButton.current.disabled) completeButton.current.focus()
      else reviewPanel.current?.focus()
    }
  }, [confirmation])

  const s = review?.summary
  const completed = Boolean(review?.lifecycle_status === 'Finding Review' && review.completion)
  const completedBy = review?.completion && currentAnalyst?.id === review.completion.actor_id && currentAnalyst.username.trim()
    ? currentAnalyst.username.trim() : null
  const ready = Boolean(review?.ready)
  const unresolved = operation.phase === 'uncertain' || operation.phase === 'submitting'
  const canBegin = Boolean(ready && review?.can_complete && csrfToken && !error && !submitting && !unresolved && !completed)
  const running = s?.active_execution_requests ?? 0
  const failed = s ? s.counts.Failed + s.counts.Stopped + s.counts.Blocked + s.counts.Cancelled : 0
  const processing = s ? s.processing_errors + s.processing_pending + s.missing_processing : 0

  function cancelConfirmation() {
    if (inFlight.current) return
    captured.current = undefined
    setConfirmation(undefined)
  }
  function openConfirmation() {
    if (!canBegin || inFlight.current || !review) return
    const snapshot = structuredClone(review)
    captured.current = snapshot
    setConfirmation(snapshot)
  }

  async function act(decisionId?: string, decision?: 'Reviewed' | 'Deferred') {
    const deciding = Boolean(decisionId && decision)
    const snapshot = captured.current
    if (inFlight.current || !review || !csrfToken || unresolved || completed) return
    if (!deciding && (!snapshot || !canBegin || snapshot.assessment_id !== assessmentId
      || snapshot.snapshot_digest !== review.snapshot_digest || snapshot.snapshot_schema_version !== review.snapshot_schema_version)) return
    if (deciding && captured.current) return
    inFlight.current = true
    setSubmitting(true)
    readGeneration.current += 1
    setError('')
    const controller = new AbortController()
    mutation.current = controller
    if (!deciding) {
      latestOperation.current = { phase: 'submitting' }
      onOperationChange(latestOperation.current)
    }
    try {
      if (decisionId && decision) {
        try {
          await decideRecommendation(assessmentId, decisionId, decision, csrfToken, controller.signal)
        } finally { onDecisionsChanged() }
        const next = await getCompletionReview(assessmentId, controller.signal)
        if (!mounted.current || controller.signal.aborted) return
        setReview(next)
        if (next.lifecycle_status === 'Finding Review' && next.completion) {
          latestOperation.current = { phase: 'confirmed', review: next }
          onOperationChange(latestOperation.current)
        }
      } else {
        const result = await completeTesting(assessmentId, snapshot!.snapshot_digest, csrfToken, controller.signal)
        if (!mounted.current || controller.signal.aborted) return
        // Task 4 has already validated the receipt, including authoritative recovery.
        latestOperation.current = { phase: 'confirmed', review: result }
        onOperationChange(latestOperation.current)
        setReview(result)
        captured.current = undefined
        setConfirmation(undefined)
      }
    } catch (failure) {
      if (!mounted.current || controller.signal.aborted) return
      captured.current = undefined
      setConfirmation(undefined)
      if (!deciding) {
        latestOperation.current = failure instanceof CompletionOutcomeUncertainError ? { phase: 'uncertain' } : { phase: 'idle' }
        onOperationChange(latestOperation.current)
      }
      setReview(undefined)
      setError(failure instanceof CompletionOutcomeUncertainError
        ? 'Completion could not be confirmed. Verify the persisted status before taking further action.'
        : failure instanceof AssessmentStartError && failure.status === 409
          ? 'The assessment changed. Refresh readiness and review the current blockers.'
          : 'The action could not be verified. Refresh before trying again.')
      if (failure instanceof AssessmentStartError && failure.status === 401) onExpired()
    } finally {
      inFlight.current = false
      mutation.current = undefined
      if (mounted.current) setSubmitting(false)
    }
  }

  return <>
    <div className="testing-metrics">{[
      ['Total Tests', s?.total], ['In Progress', s?.counts.Running],
      ['Completed', s?.counts.Completed], ['Failed', s?.counts.Failed],
    ].map(([label, value]) => <section className="analyst-card" key={label} aria-label={String(label)}>
      <p>{label}</p><strong>{value ?? '—'}</strong></section>)}</div>
    {error && <section role="alert" className="analyst-card"><p>{error}</p>
      <button type="button" className="analyst-link" disabled={submitting} onClick={() => setRetry(n => n + 1)}>Retry</button></section>}
    {unresolved && <section role="status" className="testing-notice"><div><h2>{operation.phase === 'submitting' ? 'Confirming completion…' : 'Completion outcome unverified'}</h2>
      <p>Only a persisted completion receipt can establish success. A Testing response does not prove the earlier request failed.</p>
      {operation.phase === 'uncertain' && <button type="button" className="analyst-link" onClick={() => setRetry(n => n + 1)}>Verify completion status</button>}
    </div></section>}
    {!review && !error && <p role="status">Checking completion readiness…</p>}
    {review && <section className="testing-notice" aria-label={completed ? 'Testing completed' : ready ? 'Ready to complete' : 'Completion unavailable'}>
      <img src={information} alt="" /><div>
        <h2>{completed ? 'Testing completed' : ready ? 'Ready to complete' : 'Completion unavailable'}</h2>
        <p>{completed ? 'The testing phase is complete. This assessment is now in Finding Review.'
          : ready ? 'All required completion checks have passed. Review the summary, then complete the testing phase.'
          : running ? 'Active or queued execution requests remain. Review their status before completing testing.'
          : 'Review the items requiring attention before completing the testing phase.'}</p>
      </div></section>}
    {review && <section ref={reviewPanel} tabIndex={-1} className="analyst-card testing-completion-review" aria-label={completed ? 'Testing Completed' : 'Testing Completion Review'}>
      <h2>{completed ? 'Testing Completed' : 'Testing Completion Review'}</h2>
      {completed ? <p>Testing was completed on <time dateTime={review.completion!.completed_at}>{new Date(review.completion!.completed_at).toLocaleString()}</time>{completedBy ? ` by ${completedBy}` : ` by analyst ID ${review.completion!.actor_id}`}.</p>
        : <p>Review these items before you end the testing phase.</p>}
      {!completed && !review.can_complete && review.lifecycle_status === 'Testing' && <p>Only the assessment creator can complete testing. Assigned analysts can review this assessment.</p>}
      <div className="testing-completion-checks">
        <div className="testing-completion-check">
          <div><h3>{completed ? 'Tests' : 'Running or failed tests'}</h3><p>{running ? `${running} active or queued test activities remain.`
            : failed ? `${failed} unsuccessful or interrupted tests require attention.`
            : s!.total === 0 ? 'No tests have been scheduled.' : `${s!.counts.Completed} tests completed.`}</p>
            {Boolean(s!.recovery_required_requests) && <p>{s!.recovery_required_requests} execution request(s) require recovery verification.</p>}</div>
          <span className="testing-completion-status" data-state={running || failed || !s!.total ? 'attention' : 'clear'}>{running || failed || !s!.total ? 'Needs attention' : 'Clear'}</span>
          {!completed && <button type="button" className="analyst-link" onClick={onContinue}>View Tests</button>}
        </div>
        <div className="testing-completion-check">
          <div><h3>{completed ? 'Recommendations' : 'Pending recommendations'}</h3>
            <p>{s!.decision_counts.pending_completion ? `${s!.decision_counts.pending_completion} recommendation(s) are waiting for a decision.` : 'No recommendations are waiting for a decision.'}</p>
            {Boolean(s!.decision_counts.deferred) && <p>{s!.decision_counts.deferred} deferred recommendation(s) still require review.</p>}</div>
          <span className="testing-completion-status" data-state={s!.decision_counts.pending_completion ? 'attention' : 'clear'}>{s!.decision_counts.pending_completion ? 'Needs attention' : 'Clear'}</span>
          {!completed && <button type="button" className="analyst-link" onClick={onRecommendations}>Review Recommendations</button>}
        </div>
        <div className="testing-completion-check">
          <div><h3>Candidate findings</h3><p>Candidate findings will be reviewed in the Findings stage. A verified candidate-finding count is not available yet.</p></div>
          <span className="testing-completion-status" data-state="next">Next stage</span>
        </div>
        <div className="testing-completion-check">
          <div><h3>Processing errors</h3><p>{processing ? `${processing} processing issue(s) or incomplete processing records require attention.` : 'No processing errors were reported.'}</p></div>
          <span className="testing-completion-status" data-state={processing ? 'attention' : 'clear'}>{processing ? 'Needs attention' : 'Clear'}</span>
        </div>
      </div>
      {!completed && review.blocker_details.filter(item => !['active_tests', 'pending_recommendations', 'unsuccessful_tests', 'processing_not_clear'].includes(item.code)).map(item => <p key={item.code}>{item.message}</p>)}
      {!completed && review.recommendations.some(item => item.decision !== 'Reviewed') && <section className="testing-completion-decisions" aria-label="Recommendation decisions">
        <h3>Recommendation decisions</h3>
        <p>Record an explicit decision for each recommendation. Deferring a recommendation does not authorize a new test or clear the completion safety gate.</p>
        {review.recommendations.filter(item => item.decision !== 'Reviewed').map(item => <div key={item.id} className="testing-completion-decision">
          <span>{item.title}{item.decision === 'Deferred' ? ' · Deferred (still requires review)' : ''}</span>
          <button type="button" disabled={submitting || unresolved || Boolean(confirmation) || !csrfToken} onClick={() => { void act(item.id, 'Reviewed') }}>Mark reviewed</button>
          <button type="button" disabled={submitting || unresolved || Boolean(confirmation) || !csrfToken} onClick={() => { void act(item.id, 'Deferred') }}>Defer</button>
        </div>)}
      </section>}
      <p className="testing-completion-help">{completed ? 'The assessment is now in Finding Review.' : ready ? 'Completing testing moves this assessment to Finding Review.' : 'Complete Testing becomes available once all required checks have passed.'}</p>
      <div className="testing-completion-actions">
        {completed ? <button type="button" className="analyst-create" onClick={onFindings}>Continue to Findings</button>
          : <><button type="button" onClick={onContinue}>Continue Testing</button>
            <button ref={completeButton} type="button" className="analyst-create" disabled={!canBegin || Boolean(confirmation)} onClick={openConfirmation}>Complete Testing</button></>}
      </div>
    </section>}
    <dialog ref={dialog} className="testing-completion-dialog" aria-labelledby="testing-completion-confirm-title"
      onCancel={event => { event.preventDefault(); cancelConfirmation() }}>
      <h2 id="testing-completion-confirm-title">Complete testing?</h2>
      <p>This ends the testing phase for {confirmation?.assessment_name}. No new tests will start, and the assessment moves to Finding Review.</p>
      <ul><li>{confirmation?.summary.counts.Completed ?? '—'} tests completed</li>
        <li>{confirmation?.summary.decision_counts.pending_completion ?? '—'} recommendations waiting for a decision</li>
        <li>Candidate findings will be reviewed in the next stage</li></ul>
      <div className="testing-completion-actions">
        <button type="button" disabled={submitting} onClick={cancelConfirmation}>Cancel</button>
        <button type="button" className="analyst-create" disabled={submitting || !canBegin || !confirmation}
          onClick={() => { void act() }}>{submitting ? 'Completing…' : 'Complete Testing'}</button>
      </div>
    </dialog>
  </>
}
