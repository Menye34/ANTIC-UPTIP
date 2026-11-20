import { AssessmentStartError, startRequest } from './assessmentStart'

export interface ServiceDiscoveryReceipt {
  execution_id: string
  assessment_id: string
  target_id: string
  ports: number[]
  consent_digest: string
  expires_at: string
  status: 'Queued' // Historical scheduling receipt, never a current status.
  execution_authorized: false
}

export class ServiceDiscoveryOutcomeUncertainError extends Error {
  constructor() { super('Service-discovery scheduling outcome is unverified.') }
}

export function parseServicePorts(text: string): number[] | null {
  const parts = text.split(',').map(value => value.trim())
  if (parts.length < 1 || parts.length > 16 || parts.some(value => !/^[1-9]\d{0,4}$/.test(value))) return null
  const ports = parts.map(Number)
  if (ports.some(port => port > 65535) || new Set(ports).size !== ports.length) return null
  return ports.sort((a, b) => a - b)
}

function validateReceipt(value: ServiceDiscoveryReceipt, assessmentId: string, targetId: string, ports: number[]) {
  if (!value || value.assessment_id !== assessmentId || value.target_id !== targetId
      || typeof value.execution_id !== 'string' || !value.execution_id
      || !Array.isArray(value.ports) || value.ports.length !== ports.length
      || value.ports.some((port, i) => port !== ports[i])
      || typeof value.consent_digest !== 'string' || !/^[a-f0-9]{64}$/.test(value.consent_digest)
      || typeof value.expires_at !== 'string' || !Number.isFinite(Date.parse(value.expires_at))
      || value.status !== 'Queued' || value.execution_authorized !== false) {
    throw new Error('Invalid service-discovery receipt.')
  }
  return value
}

export async function scheduleServiceDiscovery(assessmentId: string, targetId: string, ports: number[],
  csrf: string, key: string, signal: AbortSignal) {
  const parsed = parseServicePorts(ports.join(','))
  if (!csrf || !key || !parsed || !targetId) throw new Error('Explicit target, ports and CSRF are required.')
  try {
    const value = await startRequest<ServiceDiscoveryReceipt>(assessmentId, '/testing/service-discovery', signal, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf, 'Idempotency-Key': key },
      body: JSON.stringify({ target_id: targetId, ports: parsed, confirmed: true }),
    })
    return validateReceipt(value, assessmentId, targetId, parsed)
  } catch (failure) {
    if (failure instanceof AssessmentStartError && failure.status >= 400 && failure.status < 500) throw failure
    // A timeout, server error or malformed success cannot prove rollback. Never
    // automatically repeat the POST. Retain the key for read-only receipt lookup.
    throw new ServiceDiscoveryOutcomeUncertainError()
  }
}

export async function getServiceDiscoveryReceipt(assessmentId: string, targetId: string, ports: number[],
  key: string, signal: AbortSignal) {
  const value = await startRequest<{ assessment_id: string; receipt: ServiceDiscoveryReceipt | null }>(assessmentId,
    '/testing/service-discovery/receipts/' + encodeURIComponent(key), signal)
  if (!value || value.assessment_id !== assessmentId || !Object.hasOwn(value, 'receipt')) throw new Error('Invalid receipt lookup.')
  return value.receipt === null ? null : validateReceipt(value.receipt, assessmentId, targetId, ports)
}
