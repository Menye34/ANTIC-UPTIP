import { useEffect, useState } from 'react'
import { AssessmentRequestError, getAssessment } from '../services/assessments'
import type { Assessment } from '../services/assessments'

/** Finding Review landing. No candidate-finding API is currently available. */
export default function FindingsPage({ assessmentId, onExpired, onTesting }: {
  assessmentId: string
  onExpired: () => void
  onTesting: () => void
}) {
  const [assessment, setAssessment] = useState<Assessment>()
  const [error, setError] = useState('')
  const [retry, setRetry] = useState(0)

  useEffect(() => {
    const controller = new AbortController()
    setAssessment(undefined)
    setError('')
    void getAssessment(assessmentId, controller.signal).then(result => {
      if (!controller.signal.aborted) setAssessment(result)
    }).catch((failure: unknown) => {
      if (controller.signal.aborted) return
      if (failure instanceof AssessmentRequestError && failure.status === 401) onExpired()
      setError(failure instanceof AssessmentRequestError && [403, 404].includes(failure.status)
        ? 'Assessment unavailable.' : 'Unable to load the assessment. Try again.')
    })
    return () => controller.abort()
  }, [assessmentId, onExpired, retry])

  return <>
    <nav aria-label="Breadcrumb">Assessments <span aria-hidden="true">›</span> Findings</nav>
    <header className="testing-heading"><div><h1>Findings</h1>
      <p>Review candidate findings and supporting evidence from completed security tests.</p></div></header>
    {error && <section className="analyst-card" role="alert"><p>{error}</p>
      <button type="button" onClick={() => setRetry(n => n + 1)}>Retry</button></section>}
    {!assessment && !error && <p role="status">Loading assessment…</p>}
    {assessment && <section className="analyst-card" aria-label="Finding Review">
      <h2>{assessment.name}</h2>
      {assessment.status === 'Finding Review' ? <>
        <p>Testing has been completed. This assessment is now in Finding Review.</p>
        <p>Candidate findings cannot yet be listed because the Findings API is not implemented. No findings or counts have been assumed.</p>
      </> : <p>This assessment has not yet reached Finding Review. Current status: {assessment.status}.</p>}
      <button type="button" onClick={onTesting}>Back to Testing</button>
    </section>}
  </>
}
