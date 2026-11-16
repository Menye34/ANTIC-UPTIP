import { useEffect, useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { requestTargets } from '../services/targets'
import {
  getAssessmentReadiness,
  confirmAssessmentStart,
  AssessmentStartError,
} from '../services/assessmentStart'
import type { AssessmentReadiness, StartReceipt } from '../services/assessmentStart'
import type { Target, BaselineAssignment } from '../services/targets'
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
  const [readiness, setReadiness] = useState<AssessmentReadiness>()
  const [readinessError, setReadinessError] = useState('')
  const [readinessAttempt, setReadinessAttempt] = useState(0)
  const [startOpen, setStartOpen] = useState(false)
  const [starting, setStarting] = useState(false)
  const [startError, setStartError] = useState('')
  const [startReceipt, setStartReceipt] = useState<StartReceipt>()
  const [selectedBaseline, setSelectedBaseline] = useState<{ target: Target; assignment: BaselineAssignment } | null>(null)
  const baselineDialog = useRef<HTMLDialogElement>(null)
  const lifecycle = startReceipt?.lifecycle_status ?? data?.status
  const isDraft = lifecycle === 'Draft'
  const isTesting = lifecycle === 'Testing'
  const canEdit = isDraft && data?.can_edit
  const field = useRef<HTMLInputElement>(null)
  const dialog = useRef<HTMLDialogElement>(null)
  const startDialog = useRef<HTMLDialogElement>(null)
  const startPending = useRef<AbortController | null>(null)
  const startAttemptKey = useRef<string | null>(null)
  const [startOutcomeUnknown, setStartOutcomeUnknown] = useState(false)
  const [reviewExpired, setReviewExpired] = useState(false)
  const currentReviewExpiry = useRef<number | null>(null)
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
  useEffect(() => () => {
    pending.current?.abort()
    startPending.current?.abort()
  }, [])

  useEffect(() => {
    if (!data || !isDraft || startReceipt) return

    const controller = new AbortController()
    Promise.resolve().then(() => {
      if (controller.signal.aborted) return undefined
      setReadiness(undefined)
      setReadinessError('')
      return getAssessmentReadiness(id, controller.signal)
    })
      .then(result => {
        if (controller.signal.aborted || !result) return

        if (result.lifecycle_status === 'Testing' || result.lifecycle_status === 'Ready') {
          setData(current => current && { ...current, status: result.lifecycle_status, can_edit: false })
          return
        }
        const review = result?.start_review
        if (
          !review ||
          !Array.isArray(review.eligible_activities) ||
          !Array.isArray(review.excluded_activities) ||
          !Array.isArray(review.excluded_targets) ||
          typeof review.confirmation_possible !== 'boolean' ||
          !['full', 'partial', null].includes(review.mode) ||
          (review.confirmation_possible &&
            (!review.review_token || !review.mode))
        ) {
          setReadinessError(
            'Unable to verify assessment readiness. Retry the check.',
          )
          return
        }

        const expires = review.expires_at === null ? null : Date.parse(review.expires_at)
        currentReviewExpiry.current = expires
        setReviewExpired(expires !== null && (!Number.isFinite(expires) || expires <= Date.now()))
        setReadiness(result)
      })
      .catch((failure: unknown) => {
        if (controller.signal.aborted) return

        if (
          failure instanceof AssessmentStartError &&
          failure.status === 401
        ) {
          onExpired()
        } else {
          setReadinessError(
            'Unable to verify assessment readiness. Retry the check.',
          )
        }
      })

    return () => controller.abort()
  }, [id, data, isDraft, startReceipt, readinessAttempt, onExpired])
  useEffect(() => {
    if (removing && !dialog.current?.open) dialog.current?.showModal()
  }, [removing])
  useEffect(() => {
    if (selectedBaseline && !baselineDialog.current?.open) baselineDialog.current?.showModal()
    if (!selectedBaseline && baselineDialog.current?.open) baselineDialog.current.close()
  }, [selectedBaseline])

  useEffect(() => {
    if (startOpen && !startDialog.current?.open) {
      startDialog.current?.showModal()
    }
    if (!startOpen && startDialog.current?.open) {
      startDialog.current.close()
    }
  }, [startOpen])

  useEffect(() => {
    if (!isDraft || startReceipt) return
    const expiry = readiness?.start_review.expires_at
    if (!expiry) return
    const expires = Date.parse(expiry)
    if (!Number.isFinite(expires)) return
    const timer = window.setTimeout(() => {
      if (currentReviewExpiry.current === expires) setReviewExpired(true)
    }, Math.max(0, expires - Date.now()))
    return () => window.clearTimeout(timer)
  }, [readiness, isDraft, startReceipt])

  function closeRemoval() {
    dialog.current?.close()
    setRemoving(undefined)
  }

  async function save(change: NonNullable<Parameters<typeof requestTargets>[3]>) {
    if (!canEdit || pending.current) return
    const controller = new AbortController()
    pending.current = controller
    setBusy(true)
    setFieldError('')
    try {
      const result = await requestTargets(id, csrfToken, controller.signal, change)
      if (controller.signal.aborted) return
      setData(result)
      setReadiness(undefined)
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

  async function confirmStart() {
    if (!isDraft || startReceipt) return
    const review = readiness?.start_review
    if (review?.expires_at) {
      const expires = Date.parse(review.expires_at)
      if (!Number.isFinite(expires) || expires <= Date.now()) {
        setStartOpen(false)
        setStartError('The assessment review has expired. Refresh readiness before retrying.')
        setReadinessAttempt(n => n + 1)
        return
      }
    }
    if (
      !review?.confirmation_possible ||
      !review.review_token ||
      !review.mode ||
      starting ||
      startPending.current ||
      startOutcomeUnknown
    ) return

    const controller = new AbortController()
    startPending.current = controller
    startAttemptKey.current ??= crypto.randomUUID()
    setStarting(true)
    setStartError('')

    try {
      const receipt = await confirmAssessmentStart(
        id,
        csrfToken,
        review,
        startAttemptKey.current,
        controller.signal,
      )
      if (controller.signal.aborted) return

      setStartReceipt(receipt)
      setData(current => current && { ...current, status: receipt.lifecycle_status, can_edit: false })
      startAttemptKey.current = null
      setStartOpen(false)
      setReadiness(undefined)
      setReadinessAttempt(n => n + 1)
      setAttempt(n => n + 1)
    } catch (failure) {
      if (controller.signal.aborted) return

      if (failure instanceof AssessmentStartError) {
        if (failure.status === 401) {
          onExpired()
          return
        }
        if (failure.status === 409) {
          startAttemptKey.current = null
          setStartOpen(false)
          setReadiness(undefined)
          setStartError(
            'The assessment review is no longer valid. Refresh readiness before retrying.',
          )
          setReadinessAttempt(n => n + 1)
          return
        }
      }
      setStartOutcomeUnknown(true)
      setStartOpen(false)
      setStartError(
        'The confirmation outcome is unknown. Reload the assessment and verify its status before attempting Start again.',
      )
    } finally {
      if (!controller.signal.aborted) {
        startPending.current = null
        setStarting(false)
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
      <div><h1>Assessment Targets</h1><p>{isDraft ? 'Add targets, review their baselines, and start testing.' : 'Review the targets and baselines for this assessment.'}</p>
        <a className="scope-secondary target-back-link" href={overview + '/scope'}><svg aria-hidden="true" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m12 19-7-7 7-7"/><path d="M5 12h14"/></svg>Back to Authorized Scope</a></div>
      {data && <span className="assessment-badge"><img src={draftIcon} alt="" />{lifecycle}</span>}
    </header>
    {error && <div className="analyst-card" role="alert"><p>{error}</p><button className="analyst-link" onClick={() => {
      setError('')
      setAttempt(n => n + 1)
    }}>Reload targets</button></div>}
    {!data && !error && <p role="status">Loading assessment targets…</p>}
    {data && <>
      <section className="analyst-card target-list">
        <h2>Assessment Targets</h2>
        <p>{isDraft ? 'Add the targets you want to test. UPTIP will check if they are within the authorized scope.' : 'Targets included in this assessment.'}</p>
        {canEdit && <form onSubmit={submit} noValidate>
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
          {(canEdit ? ['Target', 'Type', 'Scope status', 'Eligibility', 'Actions'] : ['Target', 'Type', 'Scope status', 'Eligibility']).map(label => <th scope="col" key={label}>{label}</th>)}
        </tr></thead><tbody>
          {data.targets.map(target => <tr key={target.id}>
            <td>{target.normalized_value}</td><td>{target.kind}</td>
            <td title={target.classification_reason}>{scopeLabels[target.scope_status]}</td>
            <td data-eligibility={target.eligibility}>{isTesting && target.eligibility === 'pending' ? 'Not recorded' : target.eligibility === 'pending' ? 'Pending' : 'Blocked'}</td>
            {canEdit && <td><div className="scope-actions">
              <button className="analyst-link" aria-label={'Edit ' + target.normalized_value} disabled={busy} onClick={() => {
                setEditing(target); setValue(target.original_value); setFieldError(''); field.current?.focus()
              }}>Edit</button>
              <button className="analyst-link" aria-label={'Remove ' + target.normalized_value} disabled={busy}
                onClick={() => setRemoving(target)}>Remove</button>
            </div></td>}
          </tr>)}
          {!data.targets.length && <tr><td colSpan={canEdit ? 5 : 4}>{isDraft ? 'No targets added. Add a target to begin system preparation.' : 'No targets recorded for this assessment.'}</td></tr>}
        </tbody></table>
      </section>
      <section className="analyst-card target-baselines">
        <h2>Baseline Resolution</h2>
        <p>UPTIP automatically selects a suitable baseline for each target.</p>
        {data.targets.length ? <div className="target-table-scroll"><table aria-label="Target baseline status"><thead><tr>
          {['Target', 'Baseline', 'Status', 'Actions'].map(label => <th scope="col" key={label}>{label}</th>)}
        </tr></thead><tbody>{data.targets.flatMap(target => {
          const assignments = target.baseline_assignments ?? []
          return assignments.length ? assignments.map(assignment => <tr key={target.id + ':' + assignment.profile_id}>
            <td>{target.normalized_value}</td>
            <td>{assignment.tool} · {assignment.activity} · v{assignment.version}</td>
            <td><span className="baseline-status" data-baseline-status={assignment.status}>{baselineLabels[assignment.status]}</span></td>
            <td className="baseline-actions-cell"><button type="button" className="analyst-link" onClick={() => setSelectedBaseline({ target, assignment })}>View Details</button></td>
          </tr>) : [<tr key={target.id}><td>{target.normalized_value}</td><td>Not assigned</td>
            <td>{baselineLabels[target.baseline_summary ?? target.eligibility]}</td><td>—</td></tr>]
        })}</tbody></table></div> : <p>{isDraft ? 'Add targets to let UPTIP select their baselines.' : 'No baselines recorded for this assessment.'}</p>}
      </section>
      <section className="analyst-card">
        <h2>{isTesting ? 'Assessment Started' : 'Review & Authorization'}</h2>
        {isTesting ? <>
          <p>Assessment started successfully.</p>
          <dl className="target-counts">
            <div><dt>Total targets</dt><dd>{data.counts.total}</dd></div>
            <div><dt>Included targets</dt><dd>{startReceipt ? startReceipt.authorized_target_count : 'Not available'}</dd></div>
            <div><dt>Excluded targets</dt><dd>{startReceipt ? startReceipt.excluded_target_count : 'Not available'}</dd></div>
          </dl>
          <button className="analyst-create" type="button" disabled title="Testing page is not yet available">Go to Testing</button>
        </> : <dl className="target-counts">
          <div><dt>Total targets</dt><dd>{data.counts.total}</dd></div>
          <div><dt>In-scope targets</dt><dd>{data.targets.filter(target => target.scope_status === 'in_scope').length}</dd></div>
          <div><dt>Blocked targets</dt><dd>{data.counts.blocked}</dd></div>
        </dl>}
        {isDraft && <>
        <h3>Prepared testing activities</h3>
        {readiness && <p>{new Set(readiness.start_review.eligible_activities.map(activity => activity.target_id)).size} targets eligible for scheduling; {readiness.start_review.excluded_targets.length} targets excluded from Start.</p>}
        {!readiness && !readinessError && (
          <p role="status">Checking assessment readiness…</p>
        )}
        {readiness && (
          <p>
            {readiness.start_review.eligible_activities.length}
            {' '}activities eligible for Start authorization.
          </p>
        )}

        <h3>Applicable restrictions</h3>
        {readiness && (
          <p>
            {readiness.start_review.excluded_activities.length}
            {' '}excluded activities and{' '}
            {readiness.start_review.excluded_targets.length}
            {' '}excluded targets.
          </p>
        )}

        {readiness && !readiness.start_review.confirmation_possible && (
          <div role="status">
            <strong>Start Assessment is currently blocked.</strong>

            {readiness.start_review.excluded_activities.length > 0 && (
              <ul>
                {readiness.start_review.excluded_activities.map(activity => (
                  <li key={`${activity.target_id}:${activity.profile_id}`}>
                    {activity.activity || activity.profile_id}: {' '}
                    {activity.policy?.reason_code === activity.exclusion_code
                      ? activity.policy.reason
                      : activity.exclusion_code || 'Authorization requirements not satisfied'}
                  </li>
                ))}
              </ul>
            )}

            {readiness.reasons?.length > 0 && (
              <ul>{readiness.reasons.map(reason => (
                <li key={reason.code}>{reason.message}</li>
              ))}</ul>
            )}
            {readiness.start_review.excluded_targets.map(target => (
              <ul key={target.target_id}>{target.reasons.map(reason => (
                <li key={reason.code}>{reason.message}</li>
              ))}</ul>
            ))}
            {readiness.start_review.excluded_activities.length === 0 && (
              <p>
                No activities are currently authorized for Start confirmation,
                or the required confirmation credentials are unavailable.
              </p>
            )}
          </div>
        )}

        {reviewExpired && (
          <p role="status">The Start review has expired. Refresh it before confirming.</p>
        )}
        {readiness && (!readiness.start_review.confirmation_possible || reviewExpired) && (
          <button type="button" className="analyst-link"
            disabled={busy || starting || startOutcomeUnknown || Boolean(startReceipt)}
            onClick={() => { setStartOpen(false); setReadinessAttempt(n => n + 1) }}>
            Refresh readiness
          </button>
        )}
        {readinessError && (
          <div role="alert">
            <p>{readinessError}</p>
            <button
              type="button"
              className="analyst-link"
              onClick={() => setReadinessAttempt(n => n + 1)}
            >
              Retry readiness check
            </button>
          </div>
        )}

        {startError && (
          <p role="alert">{startError}</p>
        )}

        <div className="target-start">
          <button
            type="button"
            className="analyst-create"
            disabled={
              busy ||
              starting ||
              Boolean(startReceipt) ||
              startOutcomeUnknown ||
              !readiness?.start_review.confirmation_possible ||
              !readiness.start_review.review_token ||
              !readiness.start_review.mode ||
              reviewExpired
            }
            onClick={() => {
              setStartError('')
              setStartOpen(true)
            }}
          >
            Start Assessment
          </button>
          <small>
            Review your targets and confirm to start testing.
          </small>
        </div>
        </>}

      </section>
    </>}
    {isDraft && !startReceipt && <dialog
      ref={startDialog}
      aria-labelledby="start-assessment-title"
      onCancel={event => {
        event.preventDefault()
        if (!starting) setStartOpen(false)
      }}
    >
      <h2 id="start-assessment-title">Confirm Start Assessment</h2>
      <p>
        Review the prepared activities and restrictions before
        confirming the assessment.
      </p>

      {readiness?.start_review && (
        <>
          <p>
            <strong>Authorization mode:</strong>{' '}
            {readiness.start_review.mode === 'partial'
              ? 'Partial'
              : 'Full'}
          </p>

          <h3>Included activities</h3>
          <ul>
            {readiness.start_review.eligible_activities.map(activity => (
              <li key={activity.target_id + ':' + activity.profile_id}>
                {activity.tool || 'Security tool'} —{' '}
                {activity.activity || activity.profile_id}
              </li>
            ))}
          </ul>

          <h3>Excluded activities</h3>
          {readiness.start_review.excluded_activities.length ? (
            <ul>
              {readiness.start_review.excluded_activities.map(activity => (
                <li key={activity.target_id + ':' + activity.profile_id}>
                  {activity.activity || activity.profile_id}
                  {' — '}
                  {activity.exclusion_code || 'Not eligible'}
                </li>
              ))}
            </ul>
          ) : <p>None</p>}

          <h3>Excluded targets</h3>
          {readiness.start_review.excluded_targets.length ? (
            <ul>
              {readiness.start_review.excluded_targets.map(target => (
                <li key={target.target_id}>
                  {target.target_id}
                  {' — '}
                  {target.reasons.map(reason => reason.message).join('; ')}
                </li>
              ))}
            </ul>
          ) : <p>None</p>}
        </>
      )}

      <p>
        <strong>
          This confirmation starts Testing and queues eligible baseline activities.
          It does not execute security scanners.
        </strong>
      </p>

      <div className="scope-dialog-actions">
        <button
          type="button"
          className="scope-secondary"
          disabled={starting}
          onClick={() => setStartOpen(false)}
        >
          Cancel
        </button>
        <button
          type="button"
          className="analyst-create"
          disabled={
            starting ||
            !readiness?.start_review.confirmation_possible ||
            !readiness.start_review.review_token ||
            !readiness.start_review.mode
          }
          onClick={() => void confirmStart()}
        >
          {starting ? 'Confirming…' : 'Confirm Start Assessment'}
        </button>
      </div>
    </dialog>}

    {selectedBaseline && <dialog ref={baselineDialog} className="baseline-details-dialog" aria-labelledby="baseline-details-title"
      onCancel={event => { event.preventDefault(); setSelectedBaseline(null) }}>
      <div className="baseline-panel-header"><h2 id="baseline-details-title">Baseline Details</h2>
        <button type="button" className="analyst-link" onClick={() => setSelectedBaseline(null)} aria-label="Close baseline details">Close</button></div>
      <p>System-managed baseline</p>
      <h3>{selectedBaseline.assignment.activity} · v{selectedBaseline.assignment.version}</h3>
      <dl className="baseline-panel-fields">
        <div><dt>Target</dt><dd>{selectedBaseline.target.normalized_value}</dd></div>
        <div><dt>Tool</dt><dd>{selectedBaseline.assignment.tool}</dd></div>
        <div><dt>Profile</dt><dd>{selectedBaseline.assignment.profile_id}</dd></div>
        <div><dt>Status</dt><dd>{baselineLabels[selectedBaseline.assignment.status]}</dd></div>
        <div><dt>Baseline information</dt><dd>{selectedBaseline.assignment.reason}</dd></div>

        <div><dt>Prepared testing activities</dt><dd>{selectedBaseline.assignment.activity}</dd></div>
        <div><dt>Applicable restrictions</dt><dd>Testing is limited to the authorized scope and approved policy.</dd></div>
      </dl>
    </dialog>}
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
