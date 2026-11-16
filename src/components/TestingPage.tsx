import { useEffect, useRef, useState } from 'react'
import { AssessmentStartError } from '../services/assessmentStart'
import { getExecutionDetails, getTesting } from '../services/testing'
import type { ExecutionDetails, TestingData } from '../services/testing'
import plus from '../assets/testing/Plus.svg'
import information from '../assets/testing/Information.svg'
import marker from '../assets/testing/Marker.svg'
import './TestingPage.css'

function timestamp(value: string | null) {
  if (!value) return 'Not recorded'
  const date = new Date(value)
  return Number.isNaN(date.valueOf()) ? 'Not recorded' : date.toLocaleString()
}

function StatusMessage({ data }: { data: TestingData }) {
  const c = data.counts
  return <p>{c.queued > 0 && `${c.queued} ${c.queued === 1 ? 'test is' : 'tests are'} queued; queued tests are not running. `}
    {c.in_progress > 0 && `${c.in_progress} ${c.in_progress === 1 ? 'test is' : 'tests are'} in progress. `}
    {c.completed > 0 && `${c.completed} completed. `}{c.failed > 0 && `${c.failed} failed. `}
    {c.blocked > 0 && `${c.blocked} blocked. `}{c.stopped > 0 && `${c.stopped} stopped. `}
    {c.cancelled > 0 && `${c.cancelled} cancelled. `}Select View Details to review the latest available execution information.</p>
}

function Details({ assessmentId, executionId, onClose, onExpired }: {
  assessmentId: string; executionId: string; onClose: () => void; onExpired: () => void
}) {
  const [data, setData] = useState<ExecutionDetails>()
  const [error, setError] = useState('')
  const [retry, setRetry] = useState(0)
  const dialog = useRef<HTMLDialogElement>(null)
  useEffect(() => {
    dialog.current?.showModal()
    const controller = new AbortController()
    void getExecutionDetails(assessmentId, executionId, controller.signal).then(result => {
      if (!controller.signal.aborted) setData(result)
    }).catch((failure: unknown) => {
      if (controller.signal.aborted) return
      if (failure instanceof AssessmentStartError && failure.status === 401) onExpired()
      else setError(failure instanceof AssessmentStartError && [403, 404].includes(failure.status)
        ? 'Execution unavailable.' : 'Unable to load execution details.')
    })
    return () => controller.abort()
  }, [assessmentId, executionId, onExpired, retry])
  return <dialog className="testing-details analyst-card" ref={dialog} aria-labelledby="execution-details-title" onCancel={onClose}>
    <div className="testing-details-heading"><h2 id="execution-details-title">Execution Details</h2>
      <button type="button" className="analyst-link" onClick={onClose}>Close</button></div>
    {error ? <div role="alert"><p>{error}</p><button type="button" className="analyst-link" onClick={() => { setError(''); setRetry(n => n + 1) }}>Retry</button></div>
      : !data ? <p role="status">Loading execution details…</p> : <>
        <dl className="testing-metadata">
          <div><dt>Test</dt><dd>{data.test_name}</dd></div><div><dt>Tool</dt><dd>{data.tool}</dd></div>
          <div><dt>Target</dt><dd>{data.target}</dd></div><div><dt>Status</dt><dd>{data.status}</dd></div>
          <div><dt>Profile</dt><dd>{data.profile_id} v{data.profile_version}</dd></div>
        </dl>
        <h3>Execution attempts</h3>
        {!data.attempts.length ? <p>No execution attempt recorded. Queued does not mean Running.</p> : data.attempts.map(attempt => <p key={attempt.id}>
          Attempt {attempt.attempt_number}: {attempt.status} · Started: {timestamp(attempt.started_at)} · Finished: {timestamp(attempt.finished_at)}
          {attempt.reason_code && ` · ${attempt.reason_code}`}{attempt.recovery_reason && ` · ${attempt.recovery_reason}`}
        </p>)}
        <h3>Result processing</h3>
        {!data.processing.length ? <p>No processing outcome recorded.</p> : data.processing.map(item => <p key={item.id}>
          {item.status} · {item.observation_count} observations{item.partial && ' · Partial'}{item.error_code && ` · ${item.error_code}`}</p>)}
        <h3>Evidence summaries</h3>
        {!data.evidence.length ? <p>No scanner evidence recorded.</p> : <ul>{data.evidence.map(item => <li key={item.id}>
          {item.format} · {item.size_bytes} bytes{item.partial && ' · Partial'} · {timestamp(item.collected_at)}</li>)}</ul>}
        <p className="testing-secondary">This read-only view does not authorize scanner execution. Original tool output is not exposed by this API.</p>
      </>}
  </dialog>
}

export default function TestingPage({ assessmentId, onExpired }: { assessmentId: string; onExpired: () => void }) {
  const [data, setData] = useState<TestingData>()
  const [error, setError] = useState('')
  const [retry, setRetry] = useState(0)
  const [selected, setSelected] = useState<string>()
  const detailButton = useRef<HTMLButtonElement | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout> | undefined
    let forbidden = false
    async function load() {
      try {
        const result = await getTesting(assessmentId, controller.signal)
        if (controller.signal.aborted) return
        setData(result)
        setError('')
      } catch (failure) {
        if (controller.signal.aborted) return
        if (failure instanceof AssessmentStartError && [401, 403, 404].includes(failure.status)) {
          forbidden = true
          setData(undefined)
          setSelected(undefined)
          setError(failure.status === 401 ? 'Your session has ended. Sign in again to continue.' : 'Assessment unavailable.')
          if (failure.status === 401) onExpired()
        } else setError('Unable to refresh Testing. Retry to retrieve the latest status.')
      } finally {
        if (!controller.signal.aborted && !forbidden) timer = setTimeout(() => { void load() }, 5000)
      }
    }
    void load()
    return () => { controller.abort(); clearTimeout(timer) }
  }, [assessmentId, onExpired, retry])

  const empty = data?.counts.total === 0
  const scope = data?.authorization_scope
  return <>
    <nav aria-label="Breadcrumb">Testing</nav>
    <header className="testing-heading"><div><h1>Testing</h1>
      <p>Run security tests, check recommendations, and review your testing progress.</p></div>
      <button type="button" className="analyst-create testing-manual" disabled title="Manual testing is unavailable in this release">
        <img src={plus} alt="" />Run Manual Test</button>
    </header>
    <div className="testing-tabs" role="tablist" aria-label="Testing views">
      <button type="button" role="tab" id="test-activity-tab" aria-selected="true" aria-controls="test-activity-panel">Test Activity</button>
      <button type="button" role="tab" aria-selected="false" disabled title="Recommendations are unavailable in this release">Recommendations</button>
      <button type="button" role="tab" aria-selected="false" disabled title="Testing Completion is unavailable in this release">Testing Completion</button>
    </div>
    {error && <section className="testing-load-error analyst-card" role="alert"><p>{error}</p>
      {data && <p>Displaying the last retrieved data; current status is unverified.</p>}
      <button className="analyst-link" type="button" onClick={() => setRetry(n => n + 1)}>Retry</button></section>}
    {!data && !error && <p role="status">Loading Testing…</p>}
    {data && <div role="tabpanel" id="test-activity-panel" aria-labelledby="test-activity-tab" className="testing-panel">
      <div className="testing-metrics">{[
        ['Total Tests', data.counts.total], ['In Progress', data.counts.in_progress],
        ['Completed', data.counts.completed], ['Failed', data.counts.failed],
      ].map(([label, value]) => <section className="analyst-card" key={label} aria-label={String(label)}>
        <p>{label}</p><strong>{value}</strong></section>)}</div>
      {!empty && <section className="testing-notice" aria-label="Current Status"><img src={information} alt="" />
        <div><h2>Current Status</h2><StatusMessage data={data} /></div></section>}
      <section className={'analyst-card testing-activity' + (empty ? ' testing-activity-empty' : '')}>
        <h2>Test Activity</h2><p>{empty ? 'Tests started for this assessment will appear here.' : 'Monitor your tests and review their results.'}</p>
        {empty ? <div className="testing-empty"><div aria-hidden="true">◇</div><h3>No tests have been run yet</h3>
          <p>No baseline executions have been scheduled for this assessment. Test activity and results will appear here.</p>
          <small>Manual testing is not available in this release.</small></div>
          : <><div className="testing-table-scroll"><table aria-label="Test Activity"><thead><tr>
            {['Test', 'Tool', 'Target', 'Status', 'Actions'].map(label => <th scope="col" key={label}>{label}</th>)}
          </tr></thead><tbody>{data.executions.map(execution => <tr key={execution.id}>
            <th scope="row">{execution.test_name}</th><td>{execution.tool}</td><td>{execution.target}</td>
            <td><span className="testing-state" data-status={execution.status}>{execution.status}</span></td>
            <td><button type="button" className="analyst-link" aria-label={'View Details: ' + execution.test_name + ' on ' + execution.target}
              onClick={event => { detailButton.current = event.currentTarget; setSelected(execution.id) }}>View Details</button></td>
          </tr>)}</tbody></table></div><small>Additional tests will appear here as they are scheduled.</small></>}
      </section>
      {!empty && <>
        <section className="testing-notice"><img src={information} alt="" /><div><h2>View Test Results</h2>
          <p>Select View Details to review recorded execution attempts, processing outcomes and evidence summaries.</p></div></section>
        <div className="testing-context">
          <section className="analyst-card"><h2>Authorization &amp; Scope</h2><p>What this assessment is allowed to test.</p>
            <dl className="testing-metadata">
              <div><dt>Authorized scope</dt><dd>{scope?.scope_revision != null ? `Revision ${scope.scope_revision}` : 'Not recorded'}<small>Scope boundaries are not provided by the Testing API.</small></dd></div>
              <div><dt>Targets under test</dt><dd>{[...new Set(data.executions.map(row => row.target))].join(', ')}</dd></div>
              <div><dt>Baseline</dt><dd>{[...new Set(data.executions.map(row => `${row.test_name} v${row.profile_version}`))].join(', ')}</dd></div>
              <div><dt>Automation policy</dt><dd>{scope?.policy?.id ? `${scope.policy.id} v${scope.policy.version ?? '—'}` : 'Not provided'}</dd></div>
              <div><dt>Authorized by</dt><dd>Not provided by the Testing API.</dd></div>
            </dl></section>
          <section className="analyst-card"><h2>Discovered So Far</h2><p>Discovery and security-test results.</p>
            <div className="testing-discoveries">{['Open ports', 'Services', 'Web target'].map(label => <div key={label}><strong>—</strong><small>{label}</small></div>)}</div>
            <p>Port, service and web-target totals are not provided by this API.</p>
            {data.discovered_so_far.length ? <ul>{data.discovered_so_far.map(item => <li key={item.id}>
              {item.type === 'host_discovery' && typeof item.data?.address === 'string' && typeof item.data?.status === 'string'
                ? `${item.data.address}: ${item.data.status}` : item.type}{item.partial && ' (partial)'}</li>)}</ul> : <p>No discovery observations recorded.</p>}
          </section>
          <section className="analyst-card"><h2>Recent Activity</h2><p>Latest testing events.</p>
            {data.recent_activity.length ? <ul className="testing-events">{data.recent_activity.map((item, index) => {
              const execution = data.executions.find(row => row.id === item.execution_id)
              return <li key={item.execution_id + ':' + index}><img src={marker} alt="" /><div>
                <span>{item.event === 'execution_queued' ? `${execution?.test_name ?? 'Execution'} queued` : item.event}</span>
                <small><time dateTime={item.occurred_at}>{timestamp(item.occurred_at)}</time></small></div></li>
            })}</ul> : <p>No testing events recorded.</p>}
            <button type="button" className="analyst-link" disabled title="Audit Log is unavailable in this release">View Audit Log</button>
          </section>
        </div>
      </>}
    </div>}
    {selected && <Details key={selected} assessmentId={assessmentId} executionId={selected} onExpired={onExpired}
      onClose={() => { setSelected(undefined); detailButton.current?.focus() }} />}
  </>
}
