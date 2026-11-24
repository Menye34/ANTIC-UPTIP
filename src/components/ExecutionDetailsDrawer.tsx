import { useEffect, useRef, useState } from 'react'
import NiktoObservations from './NiktoObservations'
import { AssessmentStartError } from '../services/assessmentStart'
import { getExecutionDetails, getOriginalEvidence } from '../services/testing'
import type { ExecutionDetails, OriginalEvidence } from '../services/testing'

function time(value: string | null) { return value ? new Date(value).toLocaleString() : 'Not recorded' }
function detailsNeedRefresh(data: ExecutionDetails) {
  if (['Queued', 'Running'].includes(data.status)) return true
  if (data.execution_kind === 'recommended') return data.status !== 'Blocked'
    && (!data.recommended_result?.termination_verified || !data.recommended_result.integrity_verified)
  if (data.attempts.some(a => !['Succeeded', 'Failed', 'Stopped', 'Blocked', 'Cancelled'].includes(a.status))) return true
  if (data.processing.some(p => !['Succeeded', 'Failed', 'Interrupted'].includes(p.status))) return true
  if (data.status === 'Completed') return !data.attempts.length || !data.processing.length
    || data.attempts.at(-1)?.status !== 'Succeeded' || data.processing.some(p => p.status !== 'Succeeded')
  return !['Failed', 'Stopped', 'Blocked', 'Cancelled'].includes(data.status)
}

type Props = { assessmentId: string; executionId: string; onClose: () => void; onExpired: () => void }
export default function ExecutionDetailsDrawer(props: Props) {
  return <Drawer key={props.assessmentId + ':' + props.executionId} {...props} />
}

function EvidenceOutput({ assessmentId, executionId, source, denied }: {
  assessmentId: string; executionId: string; source: ExecutionDetails['evidence'][number]; denied: (status: number) => void
}) {
  const [data, setData] = useState<OriginalEvidence>()
  const [error, setError] = useState('')
  const [retry, setRetry] = useState(0)
  const { id, sha256, size_bytes, format, partial, collected_at } = source
  const callback = useRef(denied)
  useEffect(() => { callback.current = denied }, [denied])
  useEffect(() => {
    const controller = new AbortController()
    void getOriginalEvidence(assessmentId, executionId, { id, sha256, size_bytes, format, partial, collected_at }, controller.signal).then(value => {
      if (!controller.signal.aborted) { setData(value); setError('') }
    }).catch((failure: unknown) => {
      if (controller.signal.aborted) return
      setData(undefined)
      if (failure instanceof AssessmentStartError && [401, 403, 404].includes(failure.status)) callback.current(failure.status)
      else setError('Original output is unavailable or could not be verified. No unverified content is displayed.')
    })
    return () => controller.abort()
  }, [assessmentId, executionId, id, sha256, size_bytes, format, partial, collected_at, retry])
  return <>{error ? <div role="alert"><p>{error}</p><button type="button" onClick={() => setRetry(n => n + 1)}>Retry original output</button></div>
    : !data ? <p role="status">Loading verified original output…</p> : <>
      {data.partial && <p role="status">Partial evidence — this is not a complete scanner result.</p>}
      <pre className="testing-original-output" tabIndex={0}>{data.content}</pre>
    </>}</>
}

function OriginalOutput({ data, assessmentId, denied }: {
  data: ExecutionDetails; assessmentId: string; denied: (status: number) => void
}) {
  const [open, setOpen] = useState(false)
  const [selected, setSelected] = useState('')
  const source = data.evidence.find(e => e.id === selected) ?? data.evidence.find(e => e.format === 'nmap-xml') ?? data.evidence[0]
  return <details className="testing-detail-section" onToggle={event => setOpen(event.currentTarget.open)}>
    <summary>Original Tool Output</summary>
    {!source ? <p>No original tool output recorded.</p> : <>
      {data.evidence.length > 1 && <label>Evidence record<select value={source.id} onChange={event => setSelected(event.target.value)}>
        {data.evidence.map(e => <option key={e.id} value={e.id}>{e.format} · {e.size_bytes} bytes · {time(e.collected_at)}</option>)}
      </select></label>}
      <p>{source.format} · {source.size_bytes} bytes · integrity checked by the server before display</p>
      {open && <EvidenceOutput key={source.id} assessmentId={assessmentId} executionId={data.id} source={source} denied={denied} />}
    </>}
  </details>
}

function Drawer({ assessmentId, executionId, onClose, onExpired }: Props) {
  const [data, setData] = useState<ExecutionDetails>()
  const [error, setError] = useState('')
  const [retry, setRetry] = useState(0)
  const callbacks = useRef({ onClose, onExpired })
  const forbidden = useRef(false)
  const [accessDenied, setAccessDenied] = useState(false)
  const dialog = useRef<HTMLDialogElement>(null)
  useEffect(() => { callbacks.current = { onClose, onExpired } }, [onClose, onExpired])
  useEffect(() => {
    const trigger = document.activeElement instanceof HTMLElement ? document.activeElement : null
    const element = dialog.current
    element?.showModal()
    return () => { element?.close(); if (trigger?.isConnected) trigger.focus() }
  }, [])
  function denied(status: number) {
    forbidden.current = true
    setAccessDenied(true)
    setData(undefined)
    setError(status === 401 ? 'Your session has ended.' : 'Execution unavailable.')
    if (status === 401) callbacks.current.onExpired()
  }
  useEffect(() => {
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout> | undefined
    async function load() {
      if (controller.signal.aborted || forbidden.current) return
      let refresh = true
      try {
        const result = await getExecutionDetails(assessmentId, executionId, controller.signal)
        if (controller.signal.aborted || forbidden.current) return
        setData(result); setError('')
        refresh = detailsNeedRefresh(result)
      } catch (failure) {
        if (controller.signal.aborted) return
        if (failure instanceof AssessmentStartError && [401, 403, 404].includes(failure.status)) {
          forbidden.current = true; setAccessDenied(true); setData(undefined)
          setError(failure.status === 401 ? 'Your session has ended.' : 'Execution unavailable.')
          if (failure.status === 401) callbacks.current.onExpired()
        } else setError('Unable to refresh execution details. Previously retrieved information is not verified as current.')
      } finally {
        if (refresh && !controller.signal.aborted && !forbidden.current) timer = setTimeout(() => void load(), 5000)
      }
    }
    void load()
    return () => { controller.abort(); clearTimeout(timer) }
  }, [assessmentId, executionId, retry])

  const services = (data?.observations ?? []).filter(o => {
    const d = o.data
    return o.type === 'service_discovery' && d.state === 'open' && d.transport === 'tcp'
      && typeof d.port === 'number' && Number.isInteger(d.port) && d.port > 0 && d.port <= 65535 && typeof d.service === 'string'
  })
  const relatedServices = (data?.related_service_observations ?? []).filter(o => {
    const d = o.data
    return o.type === 'service_discovery' && !o.partial
      && d.state === 'open' && d.transport === 'tcp'
      && typeof d.port === 'number' && Number.isInteger(d.port)
      && d.port > 0 && d.port <= 65535
      && typeof d.service === 'string'
  })

  const niktoObservations = (data?.observations ?? []).filter(
    o => o.type === 'http_server_test'
      && typeof o.data.message === 'string'
      && typeof o.data.path === 'string'
  )
  const title = data?.status === 'Running' ? 'Running Test Details' : data?.status === 'Failed' ? 'Failed Test Details' : 'Test Details'
  return <dialog className="testing-review-dialog testing-execution-drawer" ref={dialog} aria-labelledby="execution-details-title" onCancel={event => { event.preventDefault(); onClose() }}>
    <header className="testing-review-header"><h2 id="execution-details-title">{title}</h2>
      <button type="button" aria-label="Close test details" onClick={onClose}>×</button></header>
    <div className="testing-review-body">
      {error && <div role="alert"><p>{error}</p>{!accessDenied && <button type="button" onClick={() => setRetry(n => n + 1)}>Retry</button>}</div>}
      {!data && !error ? <p role="status">Loading execution details…</p> : data && <>
        <section className="testing-detail-summary testing-test-information" aria-label="Test information">
          <h3>Test Information</h3>
          <div className="testing-test-information-header">
            <strong>{data.test_name}</strong>
            <span className="testing-state" data-status={data.status}>{data.status}</span>
          </div>
          <dl className="testing-test-information-grid">
            <div>
              <dt>Security Tool</dt>
              <dd>{data.tool}</dd>
            </div>
            <div>
              <dt>Target IP Address</dt>
              <dd>{data.target}</dd>
            </div>
            {data.execution_kind === 'recommended' && data.authorized_activity && <>
              <div>
                <dt>Target Port</dt>
                <dd>{data.authorized_activity.port}</dd>
              </div>
              <div>
                <dt>Protocol</dt>
                <dd>{data.authorized_activity.scheme.toUpperCase()}</dd>
              </div>
            </>}
          </dl>
        </section>
        {(!['Queued', 'Running'].includes(data.status) && detailsNeedRefresh(data)) && (
          <p className="testing-detail-status" role="status">
            Execution details are incomplete or uncertain; completion cannot be verified from this snapshot.
          </p>
        )}
        {data.status === 'Queued' && (
          <p className="testing-detail-status" role="status">
            This test is queued and has not started.
          </p>
        )}
        {data.status === 'Running' && (
          <p className="testing-detail-status" role="status">
            Test execution is in progress.
          </p>
        )}
        {data.status === 'Failed' && <section aria-label="Failure information"><h3>Failure Information</h3><p>{data.recommended_result?.failure_reason ?? data.attempts.at(-1)?.reason_code ?? 'Not recorded'}</p></section>}
        {data.dispatch_status === 'dispatch_blocked' && (
          <section
            className="testing-detail-section"
            aria-label="Recorded dispatch outcome"
          >
            <h3>Recorded Dispatch Outcome</h3>
            <p>Dispatch blocked</p>
            <p>Blocking reason: {data.dispatch_history?.reason_code ?? 'Not recorded'}</p>
            {data.dispatch_history && (
              <p>Recorded at: {time(data.dispatch_history.occurred_at)}</p>
            )}
            <p>
              This is a recorded dispatch outcome, not permission for a future execution.
            </p>
          </section>
        )}
        <section className="testing-detail-section" aria-label="Test results"><h3>Test Results</h3>
          {data.execution_kind === 'recommended' && niktoObservations.length === 0 && (
            <p>No normalized observations are recorded for this test.</p>
          )}
          {niktoObservations.length > 0 && (
            <NiktoObservations observations={niktoObservations} />
          )}
          {services.length ? <><p>{services.length} recorded open TCP services{services.some(o => o.partial) && ' (includes partial results)'}.</p>
            <table aria-label="Discovered ports and services"><thead><tr><th>Port</th><th>Service</th><th>Version</th></tr></thead><tbody>{services.map(o =>
              <tr key={o.id}><td>{String(o.data.port)}/tcp{o.partial && ' · Partial'}</td><td>{String(o.data.service).toUpperCase()}</td><td>{typeof o.data.version === 'string' ? o.data.version : 'Not identified'}</td></tr>)}</tbody></table></>
            : null}
          {data.observations.filter(o => o.type !== 'service_discovery' && o.type !== 'http_server_test').map(o =>
            o.type === 'host_discovery' ? (
              <div className="testing-host-result" key={o.id}>
                <span className="testing-host-address">{String(o.data.address ?? data.target)}</span>
                <span className="testing-host-status" data-status={String(o.data.status ?? 'unknown').toLowerCase()}>
                  {String(o.data.status ?? 'unknown').toLowerCase() === 'up' ? 'Up' : String(o.data.status ?? 'Unknown')}
                </span>
                {o.partial && <span>Partial result</span>}
              </div>
            ) : <p key={o.id}>{o.type}{o.partial && ' · Partial result'}</p>
          )}
          {data.test_name === 'Network Discovery' && relatedServices.length > 0 && (
            <div className="testing-related-services">
              <h4>Discovered Services</h4>
            <table aria-label="Related discovered ports and services">
              <thead>
                <tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr>
              </thead>
              <tbody>
                {relatedServices.map(o => (
                  <tr key={o.id}>
                    <td>{String(o.data.port)}/tcp</td>
                    <td>Open</td>
                    <td>{String(o.data.service).toUpperCase()}</td>
                    <td>{typeof o.data.version === 'string' ? o.data.version : 'Not identified'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            </div>
          )}
        </section>
        <OriginalOutput data={data} assessmentId={assessmentId} denied={denied} />
        <details className="testing-detail-section"><summary>Technical Details</summary>
          <dl className="testing-metadata"><div><dt>Execution ID</dt><dd>{data.id}</dd></div><div><dt>Profile</dt><dd>{data.profile_id} v{data.profile_version}</dd></div>
            <div><dt>Recorded dispatch status</dt><dd>{data.dispatch_status.replace(/_/g, ' ')}</dd></div></dl>
          <h3>Execution attempts</h3>{data.attempts.map(a => <p key={a.id}>Attempt {a.attempt_number}: {a.status} · {time(a.started_at)} · {time(a.finished_at)} {a.reason_code} {a.recovery_reason}</p>)}
          {!data.attempts.length && <p>{data.execution_kind === 'recommended' ? 'Recommended-test execution history is recorded in the timeline below.' : 'No execution attempt recorded. Queued does not mean Running.'}</p>}
          <h3>Result processing</h3>{data.processing.map(p => <p key={p.id}>{p.status} · {p.observation_count} observations {p.partial && '· Partial'} {p.error_code}</p>)}
          <h3>Execution timeline</h3>{data.events.map(e => <p key={e.id}>{e.event.replace(/_/g, ' ')} · {time(e.occurred_at)} · {e.reason_code}</p>)}
        </details>
      </>}
    </div>
  </dialog>
}
