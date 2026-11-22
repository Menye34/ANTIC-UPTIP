import { useEffect, useRef, useState } from 'react'
import { getRecommendations, getRecommendedStartReadiness, getRecommendedReceipt, startRecommendedTest, RecommendedStartUncertainError } from '../services/testing'
import { AssessmentStartError } from '../services/assessmentStart'
import type { Recommendation, RecommendedReadiness } from '../services/testing'

/** T-04D: the only confirmation is the dialog's Start Test action. */
export default function StartRecommendedTest({ assessmentId, recommendation, onClose, onStarted, onExpired, csrfToken, operation, onOperationChange }: {
  assessmentId: string; recommendation: Recommendation; onClose: () => void; onStarted: () => void; onExpired: () => void; csrfToken: string
  operation: 'idle' | 'uncertain' | 'confirmed'; onOperationChange: (phase: 'idle' | 'uncertain' | 'confirmed') => void
}) {
  const dialog = useRef<HTMLDialogElement>(null)
  const closeButton = useRef<HTMLButtonElement>(null)
  const [readiness, setReadiness] = useState<'checking' | 'ready' | 'blocked' | 'error'>('checking')
  const [reason, setReason] = useState('')
  const [retry, setRetry] = useState(0)
  const [starting, setStarting] = useState(false)
  const [startError, setStartError] = useState('')
  const [preview, setPreview] = useState<RecommendedReadiness>()
  const captured = useRef<RecommendedReadiness | null>(null)
  const pending = useRef(false)
  const action = useRef<AbortController | null>(null)
  const callbacks = useRef({ onStarted, onClose, onExpired, onOperationChange })
  useEffect(() => { callbacks.current = { onStarted, onClose, onExpired, onOperationChange } })
  useEffect(() => {
    const trigger = document.activeElement instanceof HTMLElement ? document.activeElement : null
    const element = dialog.current
    element?.showModal(); closeButton.current?.focus()
    return () => { action.current?.abort(); element?.close(); if (trigger?.isConnected) trigger.focus() }
  }, [])
  useEffect(() => {
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout> | undefined
    let stopped = false
    captured.current = null
    async function load() {
      try {
        const [latest, server] = await Promise.all([getRecommendations(assessmentId, controller.signal),
          getRecommendedStartReadiness(assessmentId, recommendation.id, controller.signal)])
        if (controller.signal.aborted) return
        const current = latest.recommendations.find(row => row.id === recommendation.id)
        if (!current || current.decision !== 'Reviewed' || current.review_outcome !== 'Accepted') {
          setReason('The recommendation is no longer accepted. Refresh Recommendations.'); setReadiness('blocked')
        } else if (captured.current && captured.current.snapshot_digest !== server.snapshot_digest) {
          stopped = true
          setReason('The reviewed configuration changed. Refresh readiness and review it again.'); setReadiness('blocked')
        } else {
          if (!captured.current) { captured.current = server; setPreview(server) }
          setReason(server.reason_code); setReadiness(server.ready ? 'ready' : 'blocked')
        }
      } catch (error) {
        if (controller.signal.aborted) return
        setReadiness('error')
        if (error instanceof AssessmentStartError && [401,403,404].includes(error.status)) {
          captured.current = null; setPreview(undefined); stopped = true
          if (error.status === 401) callbacks.current.onExpired()
        }
      } finally {
        if (!controller.signal.aborted && !stopped) timer = setTimeout(() => { void load() }, 5000)
      }
    }
    void load()
    return () => { controller.abort(); clearTimeout(timer) }
  }, [assessmentId, recommendation.id, retry])

  async function verifyStatus() {
    if (pending.current) return
    pending.current = true
    const controller = new AbortController(); action.current = controller
    try {
      await getRecommendedReceipt(assessmentId, recommendation.id, controller.signal)
      if (!controller.signal.aborted) { callbacks.current.onOperationChange('confirmed'); callbacks.current.onStarted(); callbacks.current.onClose() }
    } catch (error) {
      if (controller.signal.aborted) return
      if (error instanceof AssessmentStartError && error.status === 401) callbacks.current.onExpired()
      setStartError('No authoritative receipt is available yet. The scheduling outcome remains uncertain; do not submit another Start Test request.')
    } finally { pending.current = false }
  }
  async function start() {
    const snapshot = captured.current
    if (pending.current || operation !== 'idle' || readiness !== 'ready' || !csrfToken || !snapshot?.snapshot_digest) return
    pending.current = true; setStarting(true); setStartError('')
    callbacks.current.onOperationChange('uncertain')
    const controller = new AbortController(); action.current = controller
    try {
      await startRecommendedTest(assessmentId, recommendation.id, csrfToken, controller.signal, snapshot.snapshot_digest)
      if (!controller.signal.aborted) { callbacks.current.onOperationChange('confirmed'); callbacks.current.onStarted(); callbacks.current.onClose() }
    } catch (error) {
      if (controller.signal.aborted) return
      if (error instanceof AssessmentStartError && error.status === 401) callbacks.current.onExpired()
      if (!(error instanceof RecommendedStartUncertainError) && error instanceof AssessmentStartError && error.status < 500 && ![408,429].includes(error.status)) {
        callbacks.current.onOperationChange('idle'); setReadiness('blocked')
        setStartError(error.status === 409 ? 'The reviewed state changed. Refresh readiness and review it again.' : 'Start Test was rejected. Refresh readiness before another attempt.')
      } else setStartError('Test scheduling outcome is unverified. Check saved status; do not submit again.')
    } finally { if (!controller.signal.aborted) { pending.current = false; setStarting(false) } }
  }
  function refresh() { if (!pending.current && operation === 'idle') { setReadiness('checking'); setRetry(n => n + 1) } }
  return <dialog ref={dialog} className="testing-start-dialog" aria-labelledby="testing-start-title"
    onCancel={event => { event.preventDefault(); if (!pending.current) onClose() }}>
    <header className="testing-start-header"><div><h2 id="testing-start-title">Start Test</h2>
      <p>Review the approved test details before starting execution.</p></div>
      <button ref={closeButton} type="button" aria-label="Close Start Test" disabled={starting} onClick={onClose}>×</button></header>
    <div className="testing-start-body"><h3>{recommendation.proposed_test?.name ?? recommendation.title}</h3>
      <span className="testing-start-accepted">Accepted</span>
      <section><h4>Execution Details</h4><dl className="testing-start-grid">
        <div><dt>Target</dt><dd>{recommendation.target}</dd></div>
        <div><dt>Service</dt><dd>{recommendation.service ?? 'Not identified'}</dd></div>
        <div><dt>Port</dt><dd>{recommendation.port ?? 'Not identified'}</dd></div>
        <div><dt>Testing Tool</dt><dd>{recommendation.suggested_tool ?? 'Not configured'}</dd></div>
      </dl></section>
      <section><h4>Test Configuration</h4><dl>
        <div><dt>Configured Test Profile</dt><dd>{preview?.configured_profile ?? 'Not configured'}</dd></div>
        <div><dt>Target Endpoint</dt><dd>{preview?.endpoint ?? 'Not available'}</dd></div>
      </dl></section>
      <section><h4>Execution Readiness</h4><p role="status">{operation === 'uncertain' ? 'Scheduling outcome unverified'
        : operation === 'confirmed' ? 'Test already requested' : readiness === 'checking' ? 'Checking readiness…'
        : readiness === 'ready' ? 'Ready to Start' : readiness === 'error' ? 'Unable to verify execution readiness.' : `Unavailable — ${reason}`}</p>
        {readiness === 'ready' && operation === 'idle'
          ? <p>Required preliminary checks have passed. UPTIP will revalidate authorization and safety conditions when execution is requested.</p>
          : <p>No new execution is authorized by this view. Queued does not mean Running.</p>}
        {startError && <p role="alert">{startError}</p>}
        {operation !== 'idle' && <button type="button" onClick={() => void verifyStatus()}>Check scheduling status</button>}
        {operation === 'idle' && ['error','blocked'].includes(readiness) && <button type="button" onClick={refresh}>Refresh readiness</button>}
      </section>
    </div>
    <footer className="testing-start-footer"><button type="button" disabled={starting} onClick={onClose}>Cancel</button>
      <button type="button" className="analyst-create" disabled={starting || operation !== 'idle' || readiness !== 'ready' || !csrfToken} onClick={() => void start()}>{starting ? 'Starting…' : 'Start Test'}</button>
    </footer>
  </dialog>
}
