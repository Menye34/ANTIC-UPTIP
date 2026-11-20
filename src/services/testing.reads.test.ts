import { afterEach, expect, it, vi } from 'vitest'
import { getOriginalEvidence, getTesting } from './testing'
import { assessmentId, testingData } from '../test-fixtures/testing'
afterEach(() => vi.unstubAllGlobals())
const source = { id: 'e', format: 'nmap-xml', sha256: 'a'.repeat(64), size_bytes: 4, partial: false, collected_at: '2026-11-20T10:00:00Z' }
const value = { assessment_id: assessmentId, execution_id: 'x', evidence_id: 'e', format: 'nmap-xml',
  sha256: source.sha256, size_bytes: 4, partial: false, content: 'text' }
const reply = (data: unknown) => new Response(JSON.stringify(data), { headers: { 'Content-Type': 'application/json' } })
it('uses only authenticated read-only evidence retrieval and validates its identity and size', async () => {
  const fetcher = vi.fn().mockResolvedValue(reply(value)); vi.stubGlobal('fetch', fetcher)
  expect(await getOriginalEvidence(assessmentId, 'x', source, new AbortController().signal)).toEqual(value)
  expect(fetcher.mock.calls[0][1].credentials).toBe('same-origin')
  expect(fetcher.mock.calls[0][1].cache).toBe('no-store')
  expect(fetcher.mock.calls[0][1].method).toBeUndefined()
})
it.each([{ assessment_id: 'other' }, { execution_id: 'other' }, { evidence_id: 'other' },
  { sha256: 'b'.repeat(64) }, { content: 'longer' }, { size_bytes: -1 }, { partial: true }, { format: 'html' }])(
  'rejects contradictory original-evidence responses: %j', async changes => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(reply({ ...value, ...changes })))
    await expect(getOriginalEvidence(assessmentId, 'x', source, new AbortController().signal)).rejects.toThrow('Invalid original evidence')
  })
it.each([{ open_ports: -1, services: 1, web_targets: null }, { open_ports: '1', services: 1, web_targets: null }])(
  'rejects invalid discovery totals instead of showing misleading counts', async discovery_totals => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(reply({ ...testingData(), discovery_totals })))
    await expect(getTesting(assessmentId, new AbortController().signal)).rejects.toThrow('Invalid Testing context')
  })
