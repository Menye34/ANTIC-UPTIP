import { useEffect, useRef, useState } from 'react'
import type { FormEvent } from 'react'
import AssessmentTargets from './AssessmentTargets'
import AuthorizedScope from './AuthorizedScope'
import AnalystShell from './AnalystShell'
import { AssessmentRequestError, createAssessment, getAssessment } from '../services/assessments'
import type { Assessment } from '../services/assessments'
import createdIcon from '../assets/assessment/created.svg'
import dismissIcon from '../assets/assessment/dismiss.svg'
import './AssessmentPage.css'

interface AssessmentPageProps {
  path: string
  userId: string
  username: string
  csrfToken: string
  showCreated: boolean
  navigate: (path: string, createdBy?: string) => void
  onExpired: () => void
  signingOut: boolean
  logoutFailed: boolean
  onSignOut: () => void
}

const dashboardPath = '/analyst/dashboard'
type DateIssue = { field: 'start_date' | 'end_date'; message: string }

function DraftBadge({ status = 'Draft' }: { status?: Assessment['status'] }) {
  return <span className="assessment-badge">{status}</span>
}

function CreateForm({ userId, username, csrfToken, navigate, onExpired }: AssessmentPageProps) {
  const [nameError, setNameError] = useState('')
  const [dateError, setDateError] = useState<DateIssue | null>(null)
  const pendingKeys = useRef(new Map<string, string>())
  const [requestError, setRequestError] = useState('')
  const [saving, setSaving] = useState(false)
  const inFlight = useRef<AbortController | null>(null)
  useEffect(() => () => inFlight.current?.abort(), [])

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (inFlight.current || !username) return
    const form = event.currentTarget
    const values = new FormData(form)
    const name = String(values.get('name') ?? '').trim()
    const description = String(values.get('description') ?? '').trim()
    const start = form.elements.namedItem('start_date') as HTMLInputElement
    const end = form.elements.namedItem('end_date') as HTMLInputElement
    const nameMessage = name ? '' : 'Enter an assessment name.'
    const invalidField = !start.validity.valid ? 'start_date' : !end.validity.valid ? 'end_date' : null
    const reversed = start.value && end.value && end.value < start.value
    const dateIssue: DateIssue | null = invalidField ? { field: invalidField, message: 'Enter a valid testing date.' }
      : reversed ? { field: 'end_date', message: 'End date must be on or after the start date.' } : null
    setNameError(nameMessage)
    setDateError(dateIssue)
    setRequestError('')
    const invalidInput = nameMessage ? 'name' : dateIssue?.field
    if (invalidInput) {
      const input = form.elements.namedItem(invalidInput) as HTMLInputElement
      input.focus()
      return
    }
    const controller = new AbortController()
    inFlight.current = controller
    setSaving(true)
    try {
      const draft = { name, description: description || null, start_date: start.value || null, end_date: end.value || null }
      const payload = JSON.stringify(draft)
      const key = pendingKeys.current.get(payload) ?? crypto.randomUUID()
      pendingKeys.current.set(payload, key)
      const saved = await createAssessment(draft, csrfToken, key, controller.signal)
      if (!controller.signal.aborted) navigate('/analyst/assessments/' + saved.id, userId)
    } catch (error) {
      if (controller.signal.aborted) return
      if (error instanceof AssessmentRequestError && error.status === 401) onExpired()
      else setRequestError(error instanceof AssessmentRequestError && error.status === 422
        ? 'Check the assessment name and testing dates and try again.'
        : 'The assessment save could not be confirmed. Retry with the same details.')
    } finally {
      inFlight.current = null
      if (!controller.signal.aborted) setSaving(false)
    }
  }

  return <>
    <nav aria-label="Breadcrumb"><a href={dashboardPath}>Assessments</a> <span aria-hidden="true">›</span> <span aria-current="page">Create Assessment</span></nav>
    <div className="analyst-heading"><div><h1>Create Assessment</h1>
      <p>Enter the basic details of the assessment. Scope and targets are defined after it is created.</p>
    </div></div>
    <form className="analyst-card assessment-form" noValidate onSubmit={event => void submit(event)} aria-busy={saving}>
      <h2>Assessment details</h2>
      <div className="assessment-field assessment-name">
        <label htmlFor="assessment-name">Assessment name *</label>
        <input id="assessment-name" name="name" required maxLength={200} placeholder="Enter assessment name"
          aria-invalid={!!nameError} aria-describedby="assessment-name-hint" onChange={() => setNameError('')} />
        <small id="assessment-name-hint" className={nameError ? 'assessment-error' : undefined}>{nameError || 'Enter a name for this assessment.'}</small>
      </div>
      <div className="assessment-field">
        <label htmlFor="assessment-description">Description</label>
        <textarea id="assessment-description" name="description" maxLength={4000} placeholder="Describe the purpose or context of this assessment" />
        <small>Optional</small>
      </div>
      <fieldset className="assessment-window">
        <legend>Testing window</legend>
        <div className="assessment-dates">
          <div className="assessment-field">
            <label htmlFor="assessment-start">Start date</label>
            <input id="assessment-start" type="date" name="start_date" max="9999-12-31"
              aria-invalid={dateError?.field === 'start_date'} aria-describedby="assessment-start-hint" onChange={() => setDateError(null)} />
            <small id="assessment-start-hint" className={dateError?.field === 'start_date' ? 'assessment-error' : undefined}>
              {dateError?.field === 'start_date' ? dateError.message : 'Optional'}
            </small>
          </div>
          <div className="assessment-field">
            <label htmlFor="assessment-end">End date</label>
            <input id="assessment-end" type="date" name="end_date" max="9999-12-31"
              aria-invalid={dateError?.field === 'end_date'} aria-describedby="assessment-date-hint" onChange={() => setDateError(null)} />
            <small id="assessment-date-hint" className={dateError?.field === 'end_date' ? 'assessment-error' : undefined}>{dateError?.field === 'end_date' ? dateError.message : 'Optional'}</small>
          </div>
        </div>
      </fieldset>
      <div className="assessment-field">
        <span>Lead analyst</span>
        <div className="assessment-identity">
          <span className="assessment-avatar" aria-hidden="true">{username.slice(0, 2).toUpperCase() || 'SA'}</span>
          <div><strong>{username || 'Identity unavailable'}</strong><small>Security Analyst</small></div>
        </div>
      </div>
      <div className="assessment-next">
        <h3>What happens next</h3>
        <p>Created as <DraftBadge /></p>
        <small>A reference ID is assigned automatically. After you create it, you will land on the assessment Overview.</small>
      </div>
      {requestError && <p className="assessment-error" role="alert">{requestError}</p>}
      <div className="assessment-actions">
        <button className="assessment-cancel" type="button" disabled={saving} onClick={() => navigate(dashboardPath)}>Cancel</button>
        <button className="analyst-create" type="submit" disabled={saving || !username}>{saving ? 'Saving…' : 'Create Assessment'}</button>
      </div>
    </form>
  </>
}

function testingWindow(assessment: Assessment) {
  if (assessment.start_date && assessment.end_date) return `${assessment.start_date} – ${assessment.end_date}`
  if (assessment.start_date) return `From ${assessment.start_date}`
  if (assessment.end_date) return `Until ${assessment.end_date}`
  return 'Not set'
}

function Overview({ path, showCreated, onExpired }: AssessmentPageProps) {
  const [assessment, setAssessment] = useState<Assessment | null>(null)
  const [error, setError] = useState('')
  const [confirmed, setConfirmed] = useState(showCreated)
  useEffect(() => {
    const controller = new AbortController()
    void getAssessment(path.split('/').at(-1) ?? '', controller.signal).then(result => {
      if (!controller.signal.aborted) setAssessment(result)
    }).catch(reason => {
      if (controller.signal.aborted) return
      if (reason instanceof AssessmentRequestError && reason.status === 401) onExpired()
      else setError(reason instanceof AssessmentRequestError && [403, 404, 422].includes(reason.status)
        ? 'Assessment unavailable.' : 'The assessment could not be loaded. Please try again.')
    })
    return () => controller.abort()
  }, [path, onExpired])
  useEffect(() => {
    if (!assessment || !confirmed) return
    const timer = window.setTimeout(() => setConfirmed(false), 8000)
    return () => window.clearTimeout(timer)
  }, [assessment, confirmed])

  if (error) return <section className="analyst-card" role="alert"><p>{error}</p><a href={dashboardPath}>Back to Dashboard</a></section>
  if (!assessment) return <p role="status">Loading assessment…</p>
  const windowLabel = testingWindow(assessment)
  return <>
    <header className="assessment-overview-heading">
      <div><h1>{assessment.name}</h1><DraftBadge status={assessment.status} /></div>
      <p>Assessment overview</p>
      <div className="assessment-meta"><small>Reference: {assessment.reference}</small>
        <small>Lead: {assessment.lead_analyst}</small><small>Testing window: {windowLabel}</small></div>
    </header>
    {confirmed && <section className="assessment-success" role="status">
      <img src={createdIcon} alt="" />
      <div><strong>Assessment created</strong>
        <p>{assessment.name} has been created as Draft. Continue setup to define scope and targets.</p></div>
      <button type="button" aria-label="Dismiss confirmation" onClick={() => setConfirmed(false)}><img src={dismissIcon} alt="" /></button>
    </section>}
    <section className="assessment-setup">
      <div><h2>Assessment setup required</h2><p>Define the authorized scope and add your targets. The system classifies them and prepares the baseline automatically.</p></div>
      <a className="analyst-create" href={`/analyst/assessments/${assessment.id}/scope`}>Continue Setup</a>
    </section>
    <div className="assessment-overview-columns">
      <div className="analyst-stack">
        <section className="analyst-card"><h2>Authorized scope</h2><h3>{assessment.scope_entry_count ? `${assessment.scope_entry_count} authorized scope entries` : 'No authorized scope defined'}</h3>
          <p>Define the boundaries within which assessment activity is permitted.</p></section>
        <section className="analyst-card"><h2>Targets</h2><strong className="assessment-target-count">{assessment.target_count ?? 0} {(assessment.target_count ?? 0) === 1 ? 'target' : 'targets'}</strong>
          {!assessment.target_count && <p>No targets have been added yet.</p>}<small>Each target is classified and its baseline is prepared automatically.</small></section>
      </div>
      <div className="analyst-stack">
        <section className="analyst-card"><h2>Assessment details</h2>
          <dl className="assessment-details">
            <div><dt>Description</dt><dd>{assessment.description || 'Not provided'}</dd></div>
            <div><dt>Lead analyst</dt><dd>{assessment.lead_analyst}<small>Security Analyst</small></dd></div>
            <div><dt>Testing window</dt><dd>{windowLabel}</dd></div>
          </dl>
        </section>
        <section className="analyst-card"><h2>Recent activity</h2><strong>Assessment created</strong>
          <p><small>{assessment.created_by} · <time dateTime={assessment.created_at}>{new Date(assessment.created_at).toLocaleString()}</time></small></p>
          <button className="analyst-link" type="button" disabled title="Audit Log is unavailable in this release">View Audit Log</button>
        </section>
      </div>
    </div>
  </>
}

export default function AssessmentPage(props: AssessmentPageProps) {
  const create = props.path.endsWith('/new')
  const targets = props.path.endsWith('/targets')
  const scopeOverview = /\/(scope|targets)$/.test(props.path) ? props.path.replace(/\/(scope|targets)$/, '') : undefined
  return <AnalystShell targetsActive={targets} scopeOverview={scopeOverview} sidebar={create || Boolean(scopeOverview)} createActive={create} displayName={props.username}
    initials={props.username.slice(0, 2).toUpperCase()} signingOut={props.signingOut} onSignOut={props.onSignOut}>
    <main className={create ? 'analyst-content' : 'analyst-content assessment-overview'}>
      {props.logoutFailed && <p role="alert">Unable to sign out. Please try again.</p>}
      {create ? <CreateForm {...props} /> : scopeOverview && targets ? <AssessmentTargets overview={scopeOverview} csrfToken={props.csrfToken} onExpired={props.onExpired} />
        : scopeOverview ? <AuthorizedScope overview={scopeOverview} csrfToken={props.csrfToken} onExpired={props.onExpired} /> : <Overview {...props} />}
    </main>
  </AnalystShell>
}
