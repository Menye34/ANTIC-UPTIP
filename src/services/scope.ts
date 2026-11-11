export interface ScopeEntry {
  id: string
  value: string
  kind: string
}

export interface ScopeList {
  revision: number
  status: string
  can_edit: boolean
  entries: ScopeEntry[]
  changed?: Pick<ScopeEntry, 'value' | 'kind'>
}

export class ScopeError extends Error {
  readonly status: number
  readonly code?: string

  constructor(status: number, code?: string) {
    super('Scope request failed')
    this.status = status
    this.code = code
  }
}

export async function requestScope(assessmentId: string, signal: AbortSignal, mutation?: {
  method: 'POST' | 'PATCH' | 'DELETE'
  id?: string
  csrf: string
  revision: number
  value?: string
}) {
  const path = '/api/v1/assessments/' + encodeURIComponent(assessmentId) + '/scope'
  const response = await fetch(path + (mutation?.id ? '/' + encodeURIComponent(mutation.id) : ''), {
    credentials: 'same-origin',
    signal: AbortSignal.any([signal, AbortSignal.timeout(15000)]),
    ...(mutation && {
      method: mutation.method,
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': mutation.csrf },
      body: JSON.stringify({
        revision: mutation.revision,
        ...(mutation.method === 'DELETE' ? { confirmed: true } : { value: mutation.value }),
      }),
    }),
  })
  if (!response.ok) {
    const result = await response.json().catch(() => null)
    throw new ScopeError(response.status, result?.code)
  }
  return response.json() as Promise<ScopeList>
}

function ipv4Number(value: string) {
  const parts = value.split('.')
  if (parts.length !== 4 || !parts.every(part => /^(?:0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255)) {
    return undefined
  }
  return parts.reduce((address, part) => address * 256 + Number(part), 0)
}

function isHostname(value: string) {
  const host = value.replace(/\.$/, '')
  const labels = host.split('.')
  return host.length <= 253 && !/^(?:\d+|0x[0-9a-f]+)$/i.test(labels.at(-1) ?? '') &&
    labels.every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label))
}

// Quick field feedback. The server remains authoritative and normalizes values.
export function scopeInputError(input: string) {
  const value = input.trim()
  const invalid = 'Enter a valid IPv4 address, subnet, hostname or web URL.'
  if (!value) return 'Enter a scope entry.'
  if (!/^[!-~]{1,1024}$/.test(value) || /[\\<>"]/.test(value)) return invalid
  if (value.includes('://')) {
    const url = /^https?:\/\/([a-z0-9.-]+)(?::(\d+))?(?:[/?][^#]*)?$/i.exec(value)
    if (!url || /%(?![\da-f]{2})/i.test(value)) return invalid
    const [, host, port] = url
    if (port && (Number(port) < 1 || Number(port) > 65535)) return invalid
    return ipv4Number(host) !== undefined || isHostname(host) ? '' : invalid
  }
  if (value.includes('/')) {
    const cidr = /^([\d.]+)\/(0|[1-9]\d?)$/.exec(value)
    if (!cidr) return invalid
    const address = ipv4Number(cidr[1])
    const prefix = Number(cidr[2])
    return address !== undefined && prefix <= 32 && address % 2 ** (32 - prefix) === 0 ? '' : invalid
  }
  return ipv4Number(value) !== undefined || isHostname(value) ? '' : invalid
}
