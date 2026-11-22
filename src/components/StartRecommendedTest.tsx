import { useEffect, useRef, useState } from 'react'
import { getRecommendations, getRecommendedStartReadiness, startRecommendedTest } from '../services/testing'
import { AssessmentStartError } from '../services/assessmentStart'
import type { Recommendation } from '../services/testing'

/** T-04D. Readiness is always sourced from the server, never the Figma example. */
export default function StartRecommendedTest({ assessmentId, recommendation, onClose, onStarted, onExpired, csrfToken }: {
  assessmentId: string; recommendation: Recommendation; onClose: () => void; onStarted: () => void; onExpired: () => void; csrfToken: string
}) {
  const dialog = useRef<HTMLDialogElement>(null)
  const closeButton = useRef<HTMLButtonElement>(null)
  const [readiness, setReadiness] = useState<'checking' | 'ready' | 'blocked' | 'error'>('checking')
  const [reason, setReason] = useState('')
  const [retry, setRetry] = useState(0)
  const [starting, setStarting] = useState(false)
  const [startError, setStartError] = useState('')
  useEffect(() => {
    const trigger = document.activeElement instanceof HTMLElement ? document.activeElement : null
    const element = dialog.current
    element?.showModal()
    closeButton.current?.focus()
    return () => { element?.close(); if (trigger?.isConnected) trigger.focus() }
  }, [])
  useEffect(() => {
    const controller = new AbortController()
    setReadiness('checking')
    void Promise.all([getRecommendations(assessmentId, controller.signal),
      getRecommendedStartReadiness(assessmentId, recommendation.id, controller.signal)]).then(([latest, server]) => {
      if (controller.signal.aborted) return
      const current = latest.recommendations.find(row => row.id === recommendation.id)
      if (!current || current.decision !== 'Reviewed' || current.review_outcome !== 'Accepted') {
        setReason('The recommendation is no longer accepted. Refresh Recommendations.')
        setReadiness('blocked')
      } else if (current.suggested_tool !== 'Nikto' || current.proposed_test?.id !== 'http-server-assessment') {
        setReason('The proposed tool is not supported for execution.')
        setReadiness('blocked')
      } else if (!server.ready) {
        setReason(server.reason_code)
        setReadiness('blocked')
      } else {
        setReason('')
        setReadiness('ready')
      }
    }).catch(() => { if (!controller.signal.aborted) setReadiness('error') })
    return () => controller.abort()
  }, [assessmentId, recommendation.id, retry])
  async function start() {
    if (starting || readiness !== 'ready' || !csrfToken) return
    const controller = new AbortController()
    setStarting(true)
    setStartError('')
    try {
      await startRecommendedTest(assessmentId, recommendation.id, csrfToken, controller.signal)
      onStarted()
      onClose()
    } catch (error) {
      if (error instanceof AssessmentStartError && error.status === 401) onExpired()
      setStartError(error instanceof AssessmentStartError && error.status === 409
        ? 'The recommendation or approved scope has changed. Refresh Testing and review it again.'
        : 'Unable to start the test. Please retry.')
    } finally { setStarting(false) }
  }
  const endpoint = recommendation.service && /^(http|https)$/i.test(recommendation.service)
    && /^\d{1,3}(?:\.\d{1,3}){3}$/.test(recommendation.target)
    && Number.isInteger(recommendation.port) && recommendation.port! > 0 && recommendation.port! <= 65535
    ? `${recommendation.service.toLowerCase()}://${recommendation.target}:${recommendation.port}/` : null
  return <dialog ref={dialog} className="testing-start-dialog" aria-labelledby="testing-start-title"
    onCancel={event => { event.preventDefault(); onClose() }}>
    <header className="testing-start-header"><div><h2 id="testing-start-title">Start Test</h2>
      <p>Review the approved test details before starting execution.</p></div>
      <button ref={closeButton} type="button" aria-label="Close Start Test" onClick={onClose}>×</button></header>
    <div className="testing-start-body"><h3>{recommendation.proposed_test?.name ?? recommendation.title}</h3>
      <span className="testing-start-accepted">Accepted</span>
      <section><h4>Execution Details</h4><dl className="testing-start-grid">
        <div><dt>Target</dt><dd>{recommendation.target}</dd></div>
        <div><dt>Service</dt><dd>{recommendation.service ?? 'Not identified'}</dd></div>
        <div><dt>Port</dt><dd>{recommendation.port ?? 'Not identified'}</dd></div>
        <div><dt>Testing Tool</dt><dd>{recommendation.suggested_tool ?? 'Not configured'}</dd></div>
      </dl></section>
      <section><h4>Test Configuration</h4><dl>
        <div><dt>Configured Test Profile</dt><dd>Web Server Security Checks</dd></div>
        <div><dt>Target Endpoint</dt><dd>{endpoint ?? 'Not available'}</dd></div>
      </dl></section>
      <section><h4>Execution Readiness</h4><p role="status">{readiness === 'checking' ? 'Checking readiness…'
        : readiness === 'ready' ? 'Ready to Start'
        : readiness === 'error' ? 'Unable to verify execution readiness.'
        : `Unavailable — ${reason}`}</p>
        <p>Required preliminary checks have passed only when the recommendation remains accepted. UPTIP will revalidate authorization and safety conditions when execution is requested.</p>
        {startError && <p role="alert">{startError}</p>}
        {readiness === 'error' && <button type="button" onClick={() => setRetry(n => n + 1)}>Retry readiness check</button>}
      </section>
    </div>
    <footer className="testing-start-footer"><button type="button" onClick={onClose}>Cancel</button>
      <button type="button" className="analyst-create" disabled={starting || readiness !== 'ready' || !csrfToken} onClick={() => void start()}>{starting ? 'Starting…' : 'Start Test'}</button>
    </footer>
  </dialog>
}
