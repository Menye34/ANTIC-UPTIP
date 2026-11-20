import { useEffect, useRef, useState } from 'react'
import { AssessmentStartError } from '../services/assessmentStart'
import { getServiceDiscoveryReceipt, parseServicePorts, scheduleServiceDiscovery,
  ServiceDiscoveryOutcomeUncertainError } from '../services/serviceDiscovery'
import type { ServiceDiscoveryReceipt } from '../services/serviceDiscovery'
import type { TestingData } from '../services/testing'

type Attempt = { targetId: string; target: string; ports: number[]; key: string }
type Props = { data: TestingData; visible: boolean; available: boolean; csrfToken: string;
  onChanged: () => void; onExpired: () => void }

export default function ServiceDiscoveryScheduling({ data, visible, available, csrfToken, onChanged, onExpired }: Props) {
  const [open, setOpen] = useState(false)
  const [targetId, setTargetId] = useState('')
  const [portsText, setPortsText] = useState('')
  const [consented, setConsented] = useState(false)
  const [busy, setBusy] = useState(false)
  const [uncertain, setUncertain] = useState<Attempt>()
  const [confirmed, setConfirmed] = useState<ServiceDiscoveryReceipt>()
  const [message, setMessage] = useState('')
  const [confirmedTargets, setConfirmedTargets] = useState<string[]>([])
  const dialog = useRef<HTMLDialogElement>(null)
  const opener = useRef<HTMLButtonElement>(null)
  const inFlight = useRef(false)
  const request = useRef<AbortController | null>(null)
  const scheduled = new Set(data.executions.filter(row => row.profile_id === 'service-discovery').map(row => row.target_id))
  const targets = data.executions.filter(row => row.tool === 'Nmap' && row.profile_id === 'network-discovery'
    && row.profile_version === 2 && !scheduled.has(row.target_id) && !confirmedTargets.includes(row.target_id))
  const target = targets.find(row => row.target_id === targetId)
  const ports = parseServicePorts(portsText)
  const canRequest = available && data.lifecycle_status === 'Testing' && data.can_schedule_service_discovery === true
  const canSubmit = canRequest && Boolean(csrfToken && target && ports && consented) && !busy && !uncertain && !confirmed

  useEffect(() => () => request.current?.abort(), [])
  useEffect(() => {
    if (open) dialog.current?.showModal()
    else if (dialog.current?.open) { dialog.current.close(); opener.current?.focus() }
  }, [open])

  function close() {
    if (inFlight.current) return
    setOpen(false)
  }
  function success(receipt: ServiceDiscoveryReceipt) {
    setConfirmed(receipt)
    setConfirmedTargets(ids => [...new Set([...ids, receipt.target_id])])
    setUncertain(undefined)
    setMessage('')
    setOpen(false)
    onChanged()
  }
  async function submit() {
    if (inFlight.current || !canSubmit || !target || !ports) return
    inFlight.current = true
    setBusy(true)
    setMessage('')
    const attempt = { targetId, target: target.target, ports: [...ports], key: crypto.randomUUID() }
    const controller = new AbortController()
    request.current = controller
    try {
      const receipt = await scheduleServiceDiscovery(data.assessment_id, targetId, ports, csrfToken, attempt.key, controller.signal)
      if (!controller.signal.aborted) success(receipt)
    } catch (failure) {
      if (controller.signal.aborted) return
      if (failure instanceof ServiceDiscoveryOutcomeUncertainError) {
        setUncertain(attempt)
        setMessage('The scheduling outcome is unverified. Check the saved receipt before taking further action. Do not submit another request.')
      } else {
        setMessage(failure instanceof AssessmentStartError && failure.status === 409
          ? 'Scheduling was not accepted. The target, baseline or tool may need revalidation, or service discovery may already be scheduled. Refresh Test Activity before trying again.'
          : failure instanceof AssessmentStartError && failure.status === 401
            ? 'Your session has ended. Sign in again to continue.'
            : 'Scheduling was not accepted. Check creator permission, session security and the selected target and ports.')
        if (failure instanceof AssessmentStartError && failure.status === 401) onExpired()
        onChanged()
      }
    } finally {
      if (!controller.signal.aborted) { inFlight.current = false; setBusy(false) }
    }
  }
  async function verify() {
    if (inFlight.current || !uncertain) return
    inFlight.current = true
    setBusy(true)
    const controller = new AbortController()
    request.current = controller
    try {
      const receipt = await getServiceDiscoveryReceipt(data.assessment_id, uncertain.targetId, uncertain.ports, uncertain.key, controller.signal)
      if (controller.signal.aborted) return
      if (receipt) success(receipt)
      else setMessage('No saved receipt is visible yet. The outcome remains unverified. You can check again; do not submit another request.')
    } catch (failure) {
      if (!controller.signal.aborted) {
        setMessage('Unable to verify the saved receipt. The scheduling outcome remains uncertain.')
        if (failure instanceof AssessmentStartError && failure.status === 401) onExpired()
      }
    } finally {
      if (!controller.signal.aborted) { inFlight.current = false; setBusy(false) }
    }
  }

  if (data.lifecycle_status !== 'Testing' && !uncertain && !confirmed) return null
  return <>
    <section hidden={!visible} className="analyst-card testing-service-scheduling" aria-label="Nmap Service Discovery">
      <h2>Nmap Service Discovery</h2>
      <p>Identify TCP services on explicitly authorized ports. Host discovery alone does not identify services.</p>
      {confirmed ? <><p role="status">Service-discovery scheduling was confirmed. Check Test Activity for the current execution status; scheduled does not mean running or completed.</p>
        {canRequest && targets.length > 0 && <button type="button" className="analyst-link" onClick={() => { setConfirmed(undefined); setTargetId(''); setPortsText(''); setConsented(false); setOpen(true) }}>Schedule another target</button>}</>
        : uncertain ? <><p role="alert">{message}</p><button type="button" className="analyst-link" disabled={busy} onClick={() => void verify()}>{busy ? 'Checking…' : 'Check scheduling status'}</button></>
        : <>
          {!canRequest && <p>Service-discovery scheduling is unavailable for this session. Only the assessment creator can confirm it while Testing.</p>}
          {canRequest && !targets.length && <p>No additional targets are available. Service discovery is limited to one request per authorized target in this assessment.</p>}
          <button ref={opener} type="button" className="analyst-create" disabled={!canRequest || !csrfToken || !targets.length || busy}
            onClick={() => { setMessage(''); setConsented(false); setOpen(true) }}>Schedule Service Discovery</button>
        </>}
    </section>
    <dialog ref={dialog} className="testing-details" aria-labelledby="service-discovery-title"
      onCancel={event => { event.preventDefault(); close() }}>
      <form className="testing-service-form" onSubmit={event => { event.preventDefault(); void submit() }}>
        <h2 id="service-discovery-title">Confirm Nmap Service Discovery</h2>
        <p>Service Discovery v1 uses the fixed, restricted TCP connect and service-detection profile. Standard Nmap version-detection behavior is included. No custom commands are accepted.</p>
        <label>Authorized target<select value={targetId} disabled={busy || Boolean(uncertain)} onChange={event => { setTargetId(event.target.value); setConsented(false) }}>
          <option value="">Choose a target</option>{targets.map(row => <option key={row.target_id} value={row.target_id}>{row.target}</option>)}
        </select></label>
        <label>Authorized TCP ports<input value={portsText} disabled={busy || Boolean(uncertain)} placeholder="For example: 80,443"
          onChange={event => { setPortsText(event.target.value); setConsented(false) }} aria-describedby="service-port-help" /></label>
        <p id="service-port-help">Enter 1–16 unique ports, from 1 to 65535, separated by commas. No ranges or default ports.</p>
        {portsText && !ports && <p role="alert">Enter a valid explicit list of TCP ports.</p>}
        {target && ports && <p>Review: {target.target} · TCP ports {ports.join(', ')}.</p>}
        <label className="testing-service-consent"><input type="checkbox" checked={consented} disabled={!target || !ports || busy || Boolean(uncertain)}
          onChange={event => setConsented(event.target.checked)} />I am authorized to run active Nmap service discovery on exactly this target and these TCP ports.</label>
        <p>The server revalidates scope, baseline, tool state and policy. The worker may start the queued request immediately. Nikto and OWASP ZAP will not execute.</p>
        {!canRequest && <p role="alert">Current scheduling permission is unavailable. Refresh Test Activity before confirming.</p>}
        {!target && targetId && <p role="alert">This target is no longer available for scheduling.</p>}
        {open && message && <p role="alert">{message}</p>}
        <footer className="testing-service-actions"><button type="button" disabled={busy} onClick={close}>Close</button>
          {uncertain ? <button type="button" disabled={busy} onClick={() => void verify()}>Check scheduling status</button>
            : <button type="submit" className="analyst-create" disabled={!canSubmit}>{busy ? 'Scheduling…' : 'Confirm and Queue'}</button>}</footer>
      </form>
    </dialog>
  </>
}
