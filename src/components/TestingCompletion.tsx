import { useEffect, useRef, useState } from 'react'
import { AssessmentStartError } from '../services/assessmentStart'
import { completeTesting, decideRecommendation, getCompletionReview } from '../services/testingCompletion'
import type { CompletionReview as CompletionData } from '../services/testingCompletion'
import type { TestingData } from '../services/testing'
import information from '../assets/testing/Information.svg'

export default function TestingCompletion({ assessmentId, csrfToken, testing, onContinue, onRecommendations, onExpired }: {
  assessmentId: string
  csrfToken: string
  testing: TestingData
  onContinue: () => void
  onRecommendations: () => void
  onExpired: () => void
}) {
  const [review, setReview] = useState<CompletionData>()
  const [error, setError] = useState('')
  const [retry, setRetry] = useState(0)
  const [confirming, setConfirming] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const dialog = useRef<HTMLDialogElement>(null)
  useEffect(() => {
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout> | undefined
    let stopped = false
    async function refresh() {
      try {
        const next = await getCompletionReview(assessmentId, controller.signal)
        if (!controller.signal.aborted) { setReview(next); setError('') }
      } catch (failure) {
        if (controller.signal.aborted) return
        setReview(undefined)
        setError('Unable to verify completion readiness. Retry to retrieve the latest status.')
        if (failure instanceof AssessmentStartError && [401, 403, 404].includes(failure.status)) {
          stopped = true
          if (failure.status === 401) onExpired()
        }
      } finally {
        if (!controller.signal.aborted && !stopped && !confirming && !submitting) {
          timer = setTimeout(() => { void refresh() }, 5000)
        }
      }
    }
    void refresh()
    return () => { controller.abort(); clearTimeout(timer) }
  }, [assessmentId, onExpired, retry, confirming, submitting])

  useEffect(() => {
    if (confirming) dialog.current?.showModal()
    else dialog.current?.close()
  }, [confirming])

  const counts = testing.counts
  const s = review?.summary
  const completed = review?.lifecycle_status === 'Finding Review' && review.completion
  const busy = submitting || confirming
  const ready = Boolean(review?.ready && !error && !busy)
  const running = (s?.counts.Queued ?? counts.queued) + (s?.counts.Running ?? counts.in_progress)
    + (s?.active_attempts ?? 0)
  const failed = (s?.counts.Failed ?? counts.failed) + (s?.counts.Stopped ?? counts.stopped)
    + (s?.counts.Blocked ?? counts.blocked) + (s?.counts.Cancelled ?? counts.cancelled)
  const processing = (s?.processing_errors ?? 0) + (s?.processing_pending ?? 0) + (s?.missing_processing ?? 0)

  async function act(decisionId?: string, decision?: 'Reviewed' | 'Deferred') {
    if (!review || !csrfToken || submitting) return
    setSubmitting(true)
    setError('')
    const controller = new AbortController()
    try {
      if (decisionId && decision) await decideRecommendation(assessmentId, decisionId, decision, csrfToken, controller.signal)
      else {
        if (!review.ready || !confirming) return
        await completeTesting(assessmentId, review.snapshot_digest, csrfToken, controller.signal)
        setConfirming(false)
      }
      const next = await getCompletionReview(assessmentId, controller.signal)
      setReview(next)
      setRetry(n => n + 1)
    } catch (failure) {
      setConfirming(false)
      setReview(undefined)
      setError(failure instanceof AssessmentStartError && failure.status === 409
        ? 'The assessment changed. Refresh readiness and review the current blockers.'
        : 'The action could not be verified. Refresh before trying again.')
      if (failure instanceof AssessmentStartError && failure.status === 401) onExpired()
    } finally {
      setSubmitting(false)
    }
  }

  return <>
    <div className="testing-metrics">{[
      ['Total Tests', counts.total], ['In Progress', counts.in_progress],
      ['Completed', counts.completed], ['Failed', counts.failed],
    ].map(([label, value]) => <section className="analyst-card" key={label} aria-label={String(label)}>
      <p>{label}</p><strong>{value}</strong></section>)}</div>
    {error && <section role="alert" className="analyst-card"><p>{error}</p>
      <button type="button" className="analyst-link" onClick={() => setRetry(n => n + 1)}>Retry</button></section>}
    {!review && !error && <p role="status">Checking completion readiness…</p>}
    {review && <section className="testing-notice" aria-label={completed ? 'Testing completed' : ready ? 'Ready to complete' : 'Completion unavailable'}>
      <img src={information} alt="" /><div>
        <h2>{completed ? 'Testing completed' : ready ? 'Ready to complete' : 'Completion unavailable'}</h2>
        <p>{completed ? 'The testing phase is complete. This assessment is now in Finding Review.'
          : ready ? 'All required completion checks have passed. Review the summary, then complete the testing phase.'
          : running ? 'Tests are still queued or running. Wait for them to finish before completing testing.'
          : 'Review the items requiring attention before completing the testing phase.'}</p>
      </div></section>}
    {review && <section className="analyst-card testing-completion-review" aria-label="Testing Completion Review">
      <h2>{completed ? 'Testing Completed' : 'Testing Completion Review'}</h2>
      {completed ? <p>Testing was completed on {new Date(review.completion!.completed_at).toLocaleString()}.</p>
        : <p>Review these items before you end the testing phase.</p>}
      <div className="testing-completion-checks">
        <div className="testing-completion-check">
          <div><h3>Running or failed tests</h3><p>{running ? `${running} active or queued test activities remain.`
            : failed ? `${failed} unsuccessful or interrupted tests require attention.`
            : counts.total === 0 ? 'No tests have been scheduled.'
            : `${counts.completed} tests completed.`}</p></div>
          <span className="testing-completion-status">{running || failed || counts.total === 0 ? 'Needs attention' : 'Clear'}</span>
          {!completed && <button type="button" className="analyst-link" onClick={onContinue}>View Tests</button>}
        </div>
        <div className="testing-completion-check">
          <div><h3>Pending recommendations</h3>
            <p>{s?.pending_recommendation_ids.length
              ? `${s.pending_recommendation_ids.length} recommendation(s) are waiting for a decision.`
              : 'No recommendations are waiting for a decision.'}</p></div>
          <span className="testing-completion-status">{s?.pending_recommendation_ids.length ? 'Needs attention' : 'Clear'}</span>
          {!completed && <button type="button" className="analyst-link" onClick={onRecommendations}>Review Recommendations</button>}
        </div>
        <div className="testing-completion-check">
          <div><h3>Candidate findings</h3><p>Candidate findings will be reviewed in the Findings stage. A verified count is not available yet.</p></div>
          <span className="testing-completion-status">Next stage</span>
        </div>
        <div className="testing-completion-check">
          <div><h3>Processing errors</h3><p>{processing ? `${processing} processing issue(s) or incomplete processing records require attention.`
            : 'No outstanding processing issues were reported.'}</p></div>
          <span className="testing-completion-status">{processing ? 'Needs attention' : 'Clear'}</span>
        </div>
      </div>
      {!completed && review.recommendations.some(item => !item.decision) && <section className="testing-completion-decisions" aria-label="Recommendation decisions">
        <h3>Recommendation decisions</h3>
        <p>Record an explicit decision for each recommendation. Deferring a recommendation does not authorize a new test.</p>
        {review.recommendations.filter(item => !item.decision).map(item => <div key={item.id} className="testing-completion-decision">
          <span>{item.title}</span>
          <button type="button" disabled={submitting || !csrfToken} onClick={() => { void act(item.id, 'Reviewed') }}>Mark reviewed</button>
          <button type="button" disabled={submitting || !csrfToken} onClick={() => { void act(item.id, 'Deferred') }}>Defer</button>
        </div>)}
      </section>}
      <p className="testing-completion-help">{completed ? 'The assessment is now in Finding Review.'
        : ready ? 'Completing testing moves this assessment to Finding Review.'
          : 'Complete Testing becomes available once all required checks have passed.'}</p>
      <div className="testing-completion-actions">
        {completed ? <button type="button" disabled title="Findings route is not yet available">Continue to Findings</button>
          : <><button type="button" onClick={onContinue}>Continue Testing</button>
            <button type="button" className="analyst-create" disabled={!ready || !csrfToken}
              onClick={() => setConfirming(true)}>Complete Testing</button></>}
      </div>
    </section>}
    <dialog ref={dialog} className="testing-completion-dialog" aria-labelledby="testing-completion-confirm-title"
      onCancel={event => { event.preventDefault(); if (!submitting) setConfirming(false) }}>
      <h2 id="testing-completion-confirm-title">Complete testing?</h2>
      <p>This ends the testing phase. No new tests will start, and the assessment moves to Finding Review.</p>
      <ul><li>{counts.completed} tests completed</li>
        <li>{s?.pending_recommendation_ids.length ?? 0} recommendations waiting for a decision</li>
        <li>Candidate findings will be reviewed in the next stage</li></ul>
      <div className="testing-completion-actions">
        <button type="button" disabled={submitting} onClick={() => setConfirming(false)}>Cancel</button>
        <button type="button" className="analyst-create" disabled={submitting || !csrfToken}
          onClick={() => { void act() }}>{submitting ? 'Completing…' : 'Complete Testing'}</button>
      </div>
    </dialog>
  </>
}
