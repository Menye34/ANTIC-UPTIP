import { useEffect, useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { requestTargets } from '../services/targets'
import type { Target } from '../services/targets'
import draftIcon from '../assets/assessment/target-draft.svg'
import { ScopeError, scopeInputError } from '../services/scope'
import './AuthorizedScope.css'
import './AssessmentTargets.css'

const baselineLabels = {
  pending: 'Pending', resolved: 'Resolved', blocked: 'Blocked',
  requires_revalidation: 'Requires Revalidation', unavailable: 'Unavailable',
  no_compatible_baseline: 'No compatible baseline',
}

const scopeLabels = { in_scope: 'In scope', out_of_scope: 'Out of scope', requires_revalidation: 'Requires revalidation' }

export default function AssessmentTargets({ overview, csrfToken, onExpired }: {
  overview: string; csrfToken: string; onExpired: () => void
}) {
  const id = overview.split('/').at(-1)!
  const [data, setData] = useState<Awaited<ReturnType<typeof requestTargets>>>()
  const [error, setError] = useState('')
  const [fieldError, setFieldError] = useState('')
  const [value, setValue] = useState('')
  const [editing, setEditing] = useState<Target>()
  const [removing, setRemoving] = useState<Target>()
  const [attempt, setAttempt] = useState(0)
  const [busy, setBusy] = useState(false)
  const field = useRef<HTMLInputElement>(null)
  const dialog = useRef<HTMLDialogElement>(null)
  const pending = useRef<AbortController | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    requestTargets(id, '', controller.signal).then(result => {
      if (!controller.signal.aborted) setData(result)
    }).catch((failure: unknown) => {
      if (controller.signal.aborted) return
      if (failure instanceof ScopeError && failure.status === 401) onExpired()
      else setError('Unable to load assessment targets.')
    })
    return () => controller.abort()
  }, [id, attempt, onExpired])
  useEffect(() => () => pending.current?.abort(), [])
  useEffect(() => {
    if (removing && !dialog.current?.open) dialog.current?.showModal()
  }, [removing])

  function closeRemoval() {
    dialog.current?.close()
    setRemoving(undefined)
  }

  async function save(change: NonNullable<Parameters<typeof requestTargets>[3]>) {
    if (!data?.can_edit || pending.current) return
    const controller = new AbortController()
    pending.current = controller
    setBusy(true)
    setFieldError('')
    try {
      const result = await requestTargets(id, csrfToken, controller.signal, change)
      if (controller.signal.aborted) return
      setData(result)
      setValue('')
      setEditing(undefined)
      closeRemoval()
    } catch (failure) {
      if (controller.signal.aborted) return
      if (failure instanceof ScopeError) {
        if (failure.status === 401) return onExpired()
        if (failure.code === 'duplicate_entry') {
          setFieldError('This target already exists. Enter a different value.')
          return
        }
        if (failure.status === 422 && change.method !== 'DELETE') {
          setFieldError('Enter a valid IPv4 address, subnet, hostname or web URL.')
          return
        }
      }
      closeRemoval()
      setData(undefined)
      setEditing(undefined)
      setError('Unable to confirm the target change. Reload targets before retrying.')
    } finally {
      if (!controller.signal.aborted) {
        pending.current = null
        setBusy(false)
      }
    }
  }

  function submit(event: FormEvent) {
    event.preventDefault()
    const validation = value.trim() ? scopeInputError(value) : 'Enter a target.'
    if (validation) {
      setFieldError(validation)
      field.current?.focus()
      return
    }
    void save(editing ? { method: 'PATCH', target: editing, value } : { method: 'POST', value })
  }

  return <div className="authorized-scope assessment-targets">
    <nav aria-label="Breadcrumb"><a href={overview + '/scope'}>Setup</a> <span aria-hidden="true">›</span> Assessment Targets</nav>
    <header className="scope-heading">
      <div><h1>Assessment Targets</h1><p>Explicitly add targets, review system-prepared baselines and authorize testing.</p>
        <a className="scope-secondary" href={overview + '/scope'}>Back to Authorized Scope</a></div>
      {data && <span className="assessment-badge"><img src={draftIcon} alt="" />{data.status}</span>}
    </header>
    {error && <div className="analyst-card" role="alert"><p>{error}</p><button className="analyst-link" onClick={() => {
      setError('')
      setAttempt(n => n + 1)
    }}>Reload targets</button></div>}
    {!data && !error && <p role="status">Loading assessment targets…</p>}
    {data && <>
      <section className="analyst-card target-list">
        <h2>Assessment Targets</h2>
        <p>Add targets explicitly. UPTIP automatically classifies and checks each target against scope.</p>
        {data.can_edit && <form onSubmit={submit} noValidate>
          <div className="scope-input-row">
            <input ref={field} aria-label={editing ? 'Edit target' : 'Target'} value={value} disabled={busy} maxLength={1024}
              aria-invalid={Boolean(fieldError)} aria-describedby={fieldError ? 'target-error' : undefined}
              placeholder="IP address, subnet, hostname or web URL" autoComplete="off" spellCheck={false}
              onChange={event => { setValue(event.target.value); setFieldError('') }} />
            {editing && <button type="button" className="scope-secondary" disabled={busy} onClick={() => {
              setEditing(undefined); setValue(''); setFieldError('')
            }}>Cancel</button>}
            <button className="analyst-create" disabled={busy}>{editing ? 'Save Target' : 'Add Target'}</button>
          </div>
          {fieldError && <small id="target-error" className="scope-field-error" role="alert">{fieldError}</small>}
        </form>}
        <table aria-label="Registered targets"><thead><tr>
          {['Target', 'Type', 'Scope status', 'Eligibility', 'Actions'].map(label => <th scope="col" key={label}>{label}</th>)}
        </tr></thead><tbody>
          {data.targets.map(target => <tr key={target.id}>
            <td>{target.normalized_value}</td><td>{target.kind}</td>
            <td title={target.classification_reason}>{scopeLabels[target.scope_status]}</td>
            <td data-eligibility={target.eligibility}>{target.eligibility === 'pending' ? 'Pending' : 'Blocked'}</td>
            <td><div className="scope-actions">{data.can_edit && <>
              <button className="analyst-link" aria-label={'Edit ' + target.normalized_value} disabled={busy} onClick={() => {
                setEditing(target); setValue(target.original_value); setFieldError(''); field.current?.focus()
              }}>Edit</button>
              <button className="analyst-link" aria-label={'Remove ' + target.normalized_value} disabled={busy}
                onClick={() => setRemoving(target)}>Remove</button>
            </>}</div></td>
          </tr>)}
          {!data.targets.length && <tr><td colSpan={5}>No targets added. Add a target to begin system preparation.</td></tr>}
        </tbody></table>
        <small>Invalid or duplicate entries are rejected; blocked targets remain available for correction.</small>
      </section>
      <section className="analyst-card target-baselines">
        <h2>Baseline Resolution</h2>
        <p>System-managed • Compatible baselines are resolved automatically.</p>
        {data.targets.length ? <table aria-label="Target baseline status"><thead><tr>
          {['Target', 'Baseline', 'Status'].map(label => <th scope="col" key={label}>{label}</th>)}
        </tr></thead><tbody>{data.targets.map(target => <tr key={target.id}>
          <td>{target.normalized_value}</td>
          <td colSpan={2}>{target.baseline_assignments?.length ? <ul className="baseline-assignments">
            {target.baseline_assignments.map(assignment => <li key={assignment.profile_id}>
              <strong>{assignment.tool} · {assignment.activity} · v{assignment.version}</strong>
              <span>{baselineLabels[assignment.status]} — {assignment.reason}</span>
            </li>)}
          </ul> : baselineLabels[target.baseline_summary ?? target.eligibility]}</td>
        </tr>)}</tbody></table> : <p>No baselines resolved yet. Add assessment targets to allow UPTIP to automatically determine their compatible testing baselines.</p>}
      </section>
      <section className="analyst-card">
        <h2>Review &amp; Authorization</h2>
        <dl className="target-counts">
          <div><dt>Total targets</dt><dd>{data.counts.total}</dd></div>
          <div><dt>Eligible targets</dt><dd>{data.counts.eligible}</dd></div>
          <div><dt>Blocked targets</dt><dd>{data.counts.blocked}</dd></div>
        </dl>
        <h3>Prepared testing activities</h3><p>No activities ready for execution.</p>
        <h3>Applicable restrictions</h3><p>Testing is unavailable until current validation identifies eligible targets.</p>
        <p><strong>Start blocked — resolve target or baseline issues and revalidate.</strong></p>
        <div className="target-start"><button className="analyst-create" disabled>Start Assessment</button>
          <small>Explicit analyst authorization and final checks are required.</small></div>
      </section>
    </>}
    {removing && <dialog ref={dialog} aria-labelledby="remove-target-title" onCancel={event => {
      event.preventDefault()
      if (!busy) closeRemoval()
    }}>
      <h2 id="remove-target-title">Remove target?</h2>
      <p>Remove <strong>{removing.normalized_value}</strong> from this assessment?</p>
      <div className="scope-dialog-actions">
        <button className="scope-secondary" disabled={busy} autoFocus onClick={closeRemoval}>Cancel</button>
        <button className="analyst-create" disabled={busy} onClick={() => void save({ method: 'DELETE', target: removing })}>Remove Target</button>
      </div>
    </dialog>}
  </div>
}
