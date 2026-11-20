import { useEffect, useMemo, useState } from 'react'
import { AssessmentRequestError, getAssessment } from '../services/assessments'
import type { Assessment } from '../services/assessments'
import './FindingsPage.css'

export type FindingSeverity = 'Critical' | 'High' | 'Medium' | 'Low'
export type ConsolidatedFinding = {
  id: string; title: string; severity: FindingSeverity; affectedTarget: string; source: string
  sourceTest: string; description: string; impact: string; securityControl: string
  observedCondition: string; detectedIssue: string; remediation: string; originalToolOutput?: string
}
type Props = {
  assessmentId: string; onExpired: () => void; onTesting: () => void
  findingId?: string; onFinding?: (id: string) => void; onBack?: () => void
  /** Frontend-only input seam. Production leaves this empty until a verified Findings API exists. */
  findings?: ConsolidatedFinding[]
}
const levels: FindingSeverity[] = ['Critical', 'High', 'Medium', 'Low']

export default function FindingsPage({ assessmentId, onExpired, onTesting, findingId, onFinding, onBack, findings = [] }: Props) {
  const [assessment, setAssessment] = useState<Assessment>()
  const [error, setError] = useState('')
  const [retry, setRetry] = useState(0)
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('')
  const [source, setSource] = useState('')
  const [assistantOpen, setAssistantOpen] = useState(false)
  const [question, setQuestion] = useState('')
  const [selectedQuestion, setSelectedQuestion] = useState('')
  const [manualOpen, setManualOpen] = useState(false)

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

  const filtered = useMemo(() => findings.filter(f =>
    (!search || [f.title, f.affectedTarget].some(v => v.toLowerCase().includes(search.toLowerCase()))) &&
    (!severity || f.severity === severity) && (!source || f.source === source)), [findings, search, severity, source])
  const selected = findings.find(f => f.id === findingId)
  const sources = [...new Set(findings.map(f => f.source))]
  const inReview = assessment?.status === 'Finding Review'
  const openQuestion = (value: string) => { setSelectedQuestion(value); setQuestion('') }
  const goBack = () => { setAssistantOpen(false); setSelectedQuestion(''); onBack?.() }

  if (error) return <section className="analyst-card" role="alert"><p>{error}</p>
    <button type="button" onClick={() => setRetry(n => n + 1)}>Retry</button></section>
  if (!assessment) return <p role="status">Loading assessment…</p>

  if (findingId) return <div className="findings-detail">
    <button type="button" className="findings-text-button" onClick={goBack}>← Back to Findings</button>
    {!selected ? <section className="analyst-card" role="alert">
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
      {assistantOpen && <div className="findings-overlay" onClick={() => setAssistantOpen(false)}>
        <aside className="findings-assistant" role="dialog" aria-modal="true" aria-label="AI Assistant" onClick={event => event.stopPropagation()}>
          <header><h2>AI Assistant</h2><button type="button" aria-label="Close AI Assistant" onClick={() => setAssistantOpen(false)}>×</button></header>
          <div className="findings-assistant-body">
            <div className="findings-assistant-context"><small>About this finding</small><strong>{selected.title}</strong>
              <p><span className={`findings-severity ${selected.severity.toLowerCase()}`}>{selected.severity}</span> {selected.affectedTarget} · {selected.source}</p></div>
            <div className="findings-assistant-note"><strong>AI-generated advice</strong><p>It uses only this finding and its evidence. It never changes the finding or the tool results. Review the advice before you act on it.</p></div>
            {selectedQuestion ? <><p className="findings-assistant-query">{selectedQuestion}</p>
              <section className="findings-assistant-response" role="status"><h3>AI Assistant is unavailable</h3>
                <p>The AI service has not been connected. You can keep working on this finding without it.</p>
                {selectedQuestion === 'Explain the tool output' && !selected.originalToolOutput && <p>Not enough information: original tool output is not attached.</p>}
                <button type="button" onClick={() => setSelectedQuestion('')}>Back to Questions</button></section></>
              : <><h3>What would you like to do?</h3>
                {['Explain this finding', 'Explain the potential impact', 'Suggest a fix', 'Help write the description', 'Explain the tool output'].map(q =>
                  <button type="button" className="findings-question" key={q} onClick={() => openQuestion(q)}>{q}<span>›</span></button>)}</>}
            <form onSubmit={event => { event.preventDefault(); if (question.trim()) openQuestion(question.trim()) }}>
              <label htmlFor="finding-question">Or ask your own question</label>
              <div className="findings-ask"><input id="finding-question" value={question} onChange={event => setQuestion(event.target.value)} placeholder="Ask about this finding…" />
                <button type="submit" disabled={!question.trim()}>Ask</button></div></form>
            {!selectedQuestion && <div className="findings-earlier"><strong>Earlier questions</strong><p>No questions have been asked about this finding yet.</p></div>}
          </div></aside></div>}
    </>}
  </div>

  return <div className="findings-page">
    <nav className="findings-breadcrumb" aria-label="Breadcrumb">Findings</nav>
    <header className="findings-heading"><div><h1>Findings</h1>
      <p>Explore consolidated security findings, inspect supporting evidence, and prepare findings for reporting.</p></div>
      <button type="button" className="analyst-create" onClick={() => setManualOpen(true)}>+ Add Manual Finding</button></header>
    {!inReview && <p className="findings-lifecycle" role="status">This assessment has not yet reached Finding Review. Current status: {assessment.status}.</p>}
    <div className="findings-metrics">{(['Total Findings', ...levels] as const).map(label => {
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
        <small>{inReview ? 'Consolidated finding data has not yet been connected to this screen.' : 'Run tests from Testing or use Add Manual Finding to record an observation.'}</small>
        {!inReview && <button type="button" className="findings-text-button" onClick={onTesting}>Go to Testing</button>}</div>}
    </section>
    {manualOpen && <div className="findings-overlay" onClick={() => setManualOpen(false)}><section role="dialog" aria-modal="true" aria-label="Add Manual Finding" className="findings-manual-dialog" onClick={event => event.stopPropagation()}>
      <h2>Add Manual Finding</h2><p>Manual finding creation is not connected to the backend yet. No finding will be saved or added to the consolidated list.</p>
      <button type="button" onClick={() => setManualOpen(false)}>Close</button></section></div>}
  </div>
}
