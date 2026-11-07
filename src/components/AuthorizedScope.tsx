import { useEffect, useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { requestScope, ScopeError, scopeInputError } from '../services/scope'
import type { ScopeEntry, ScopeList } from '../services/scope'
import './AuthorizedScope.css'

const invalidEntry = 'Enter a valid IPv4 address, subnet, hostname or web URL.'

export default function AuthorizedScope({ overview, csrfToken, onExpired }: {
  overview: string
  csrfToken: string
  onExpired: () => void
}) {
  const assessmentId = overview.split('/').at(-1)!
  const [list, setList] = useState<ScopeList>()
  const [error, setError] = useState('')
  const [fieldError, setFieldError] = useState('')
  const [value, setValue] = useState('')
  const [editing, setEditing] = useState<ScopeEntry>()
  const [removing, setRemoving] = useState<ScopeEntry>()
  const [feedback, setFeedback] = useState<{ title: string; description: string }>()
  const [busy, setBusy] = useState(false)
  const [reload, setReload] = useState(0)
  const input = useRef<HTMLInputElement>(null)
  const dialog = useRef<HTMLDialogElement>(null)
  const mutation = useRef<AbortController | null>(null)
  const expired = useRef(onExpired)
  useEffect(() => { expired.current = onExpired }, [onExpired])

  useEffect(() => {
    const controller = new AbortController()
    requestScope(assessmentId, controller.signal).then(result => {
      if (!controller.signal.aborted) setList(result)
    }).catch((failure: unknown) => {
      if (controller.signal.aborted) return
      if (failure instanceof ScopeError && failure.status === 401) expired.current()
      else setError('Unable to load authorized scope. Check your access and try again.')
    })
    return () => controller.abort()
  }, [assessmentId, reload])
  useEffect(() => () => mutation.current?.abort(), [])
  useEffect(() => {
    if (removing && !dialog.current?.open) dialog.current?.showModal()
  }, [removing])

  function dismissRemoval() {
    dialog.current?.close()
    setRemoving(undefined)
  }

  function reset() {
    setValue('')
    setFieldError('')
    setEditing(undefined)
    dismissRemoval()
  }

  function retry() {
    reset()
    setError('')
    setList(undefined)
    setReload(attempt => attempt + 1)
  }

  async function save(method: 'POST' | 'PATCH' | 'DELETE', id?: string) {
    if (!list?.can_edit || mutation.current) return
    const controller = new AbortController()
    mutation.current = controller
    setBusy(true)
    setFieldError('')
    setError('')
    setFeedback(undefined)
    try {
      const result = await requestScope(assessmentId, controller.signal, {
        method, id, csrf: csrfToken, revision: list.revision, value: value.trim(),
      })
      if (controller.signal.aborted) return
      setList(result)
      const title = method === 'POST' ? 'Scope added' : method === 'PATCH' ? 'Scope updated' : 'Scope removed'
      const description = method === 'DELETE'
        ? `${result.changed?.value} was removed.`
        : `${result.changed?.value} was saved as a ${result.changed?.kind}.`
      setFeedback({ title, description })
      reset()
    } catch (failure) {
      if (controller.signal.aborted) return
      if (failure instanceof ScopeError) {
        if (failure.status === 401) return expired.current()
        if (failure.code === 'duplicate_entry') {
          setFieldError('This scope entry already exists. Enter a different value.')
          return
        }
        if (failure.status === 422 && method !== 'DELETE') {
          setFieldError(invalidEntry)
          return
        }
        if (failure.code === 'stale_revision') {
          setList(undefined)
          reset()
          setError('Authorized scope changed. Reload the entries before making another change.')
          return
        }
      }
      setError('Unable to confirm the scope change. Reload the entries before trying again.')
      setList(undefined)
      reset()
    } finally {
      if (!controller.signal.aborted) {
        mutation.current = null
        setBusy(false)
      }
    }
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const problem = scopeInputError(value)
    if (problem) {
      setFeedback(undefined)
      setFieldError(problem)
      input.current?.focus()
      return
    }
    void save(editing ? 'PATCH' : 'POST', editing?.id)
  }

  return <div className="authorized-scope">
    <nav aria-label="Breadcrumb"><a href={overview}>Assessment Overview</a> <span aria-hidden="true">›</span> Authorized Scope</nav>
    <header className="scope-heading">
      <div><h1>Authorized Scope</h1><p>Define the boundaries within which security testing is authorized.</p></div>
      {list && <span className="assessment-badge">{list.status}</span>}
    </header>
    {error && <div role="alert" className="analyst-card"><p>{error}</p><button className="analyst-link" onClick={retry}>Reload entries</button></div>}
    {!list && !error && <p role="status">Loading authorized scope…</p>}
    {list && <>
      {list.can_edit && <section className="analyst-card">
        <h2>{editing ? 'Edit Authorized Scope' : 'Add Authorized Scope'}</h2>
        <p>Add an IP address, subnet, hostname or web URL.</p>
        <form onSubmit={submit} noValidate>
          <label htmlFor="scope-entry">{editing ? 'Edit scope entry' : 'Scope entry'}</label>
          <div className="scope-input-row">
            <input id="scope-entry" ref={input} value={value} placeholder="e.g. 192.168.10.0/24" maxLength={1024}
              disabled={busy} autoComplete="off" spellCheck={false} aria-invalid={Boolean(fieldError)}
              aria-describedby="scope-entry-feedback" onChange={event => {
                setValue(event.target.value)
                setFieldError('')
                setFeedback(undefined)
              }} />
            {editing && <button type="button" className="scope-secondary" disabled={busy} onClick={reset}>Cancel</button>}
            <button className="analyst-create" disabled={busy}>{editing ? 'Save Changes' : 'Add to Scope'}</button>
          </div>
          <small id="scope-entry-feedback" className={fieldError ? 'scope-field-error' : undefined} role={fieldError ? 'alert' : undefined}>
            {fieldError || 'UPTIP automatically detects the entry type and validates its format and duplicates.'}
          </small>
        </form>
        {feedback && <div className="scope-success" role="status"><strong>{feedback.title}</strong><p>{feedback.description}</p></div>}
      </section>}
      <section className="analyst-card">
        <h2>Authorized Scope Entries</h2>
        <table>
          <thead><tr><th scope="col">Scope Entry</th><th scope="col">Detected Type</th><th scope="col">Actions</th></tr></thead>
          <tbody>{list.entries.length ? list.entries.map(entry => <tr key={entry.id}>
            <td>{entry.value}</td><td>{entry.kind}</td><td><div className="scope-actions">
              {list.can_edit && <>
                <button className="analyst-link" disabled={busy} onClick={() => {
                  setEditing(entry)
                  setValue(entry.value)
                  setFeedback(undefined)
                  setFieldError('')
                  input.current?.focus()
                }}>Edit<span className="scope-visually-hidden"> {entry.value}</span></button>
                <button className="analyst-link" disabled={busy} onClick={() => setRemoving(entry)}>
                  Remove<span className="scope-visually-hidden"> {entry.value}</span></button>
              </>}
            </div></td>
          </tr>) : <tr><td colSpan={3} className="scope-empty"><strong>No authorized scope entries yet</strong>
            <p>{list.can_edit ? 'Add your first scope entry to define the permitted testing boundaries.' : 'The assessment creator can add authorized scope entries.'}</p>
          </td></tr>}</tbody>
        </table>
      </section>
      <footer><small>Scope entries define boundaries; they do not automatically create assessment targets.</small>
        <button className="analyst-create" disabled>Continue to Assessment Targets</button></footer>
    </>}
    {removing && <dialog ref={dialog} aria-labelledby="scope-remove-title" onCancel={event => {
      event.preventDefault()
      if (!busy) dismissRemoval()
    }}>
      <h2 id="scope-remove-title">Remove authorized scope?</h2>
      <p>Remove <strong>{removing.value}</strong> from this assessment’s authorized scope.</p>
      <p>The scope change is recorded in the audit log.</p>
      <div className="scope-dialog-actions">
        <button className="scope-secondary" autoFocus disabled={busy} onClick={dismissRemoval}>Cancel</button>
        <button className="analyst-create" disabled={busy} onClick={() => void save('DELETE', removing.id)}>Confirm Removal</button>
      </div>
    </dialog>}
  </div>
}
