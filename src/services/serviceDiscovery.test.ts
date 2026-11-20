import { afterEach, expect, it, vi } from 'vitest'
import { getServiceDiscoveryReceipt, parseServicePorts, scheduleServiceDiscovery, ServiceDiscoveryOutcomeUncertainError } from './serviceDiscovery'
import { AssessmentStartError } from './assessmentStart'
const receipt = { execution_id: 'execution', assessment_id: 'assessment', target_id: 'target', ports: [80,443],
  consent_digest: 'a'.repeat(64), expires_at: '2026-11-20T10:00:00Z', status: 'Queued', execution_authorized: false }
const reply = (value: unknown, status = 200) => ({ ok: status < 400, status, json: async () => value })
afterEach(() => vi.unstubAllGlobals())
it.each(['', '0', '65536', '80,80', '80-90', 'http', '--script all', '80,,443', Array.from({length:17},(_,i)=>i+1).join(',')])('rejects invalid ports %s', value => expect(parseServicePorts(value)).toBeNull())
it('canonicalizes only explicit unique TCP port values', () => expect(parseServicePorts('443, 80')).toEqual([80,443]))
it('posts exact consent with CSRF, session credentials and an idempotency key', async () => {
  const fetcher=vi.fn(async()=>reply(receipt));vi.stubGlobal('fetch',fetcher)
  expect(await scheduleServiceDiscovery('assessment','target',[443,80],'csrf','key',new AbortController().signal)).toEqual(receipt)
  const [url,options]=fetcher.mock.calls[0] as unknown as [string,RequestInit]
  expect(url).toBe('/api/v1/assessments/assessment/testing/service-discovery')
  expect(options.credentials).toBe('same-origin');expect(options.cache).toBe('no-store')
  expect(options.headers).toMatchObject({'X-CSRF-Token':'csrf','Idempotency-Key':'key'})
  expect(JSON.parse(options.body as string)).toEqual({target_id:'target',ports:[80,443],confirmed:true})
})
it.each([401,403,404,409,422])('preserves known HTTP %s refusal',async status=>{
  vi.stubGlobal('fetch',vi.fn(async()=>reply({},status)))
  await expect(scheduleServiceDiscovery('assessment','target',[80],'csrf','key',new AbortController().signal)).rejects.toBeInstanceOf(AssessmentStartError)
})
it.each([null,{...receipt,assessment_id:'other'},{...receipt,target_id:'other'}, {...receipt,ports:[22]},
  {...receipt,consent_digest:'bad'},{...receipt,expires_at:'invalid'},{...receipt,execution_authorized:true}])('rejects malformed success without retrying',async value=>{
  const fetcher=vi.fn(async()=>reply(value));vi.stubGlobal('fetch',fetcher)
  await expect(scheduleServiceDiscovery('assessment','target',[80,443],'csrf','key',new AbortController().signal)).rejects.toBeInstanceOf(ServiceDiscoveryOutcomeUncertainError)
  expect(fetcher).toHaveBeenCalledTimes(1)
})
it('treats server errors as uncertain, never repeating POST',async()=>{
  const fetcher=vi.fn(async()=>reply({},503));vi.stubGlobal('fetch',fetcher)
  await expect(scheduleServiceDiscovery('assessment','target',[80],'csrf','key',new AbortController().signal)).rejects.toBeInstanceOf(ServiceDiscoveryOutcomeUncertainError)
  expect(fetcher).toHaveBeenCalledTimes(1)
})
it('reads the exact receipt key and accepts historical expired scheduling receipts',async()=>{
  const fetcher=vi.fn(async()=>reply({assessment_id:'assessment',receipt}));vi.stubGlobal('fetch',fetcher)
  expect(await getServiceDiscoveryReceipt('assessment','target',[80,443],'exact-key',new AbortController().signal)).toEqual(receipt)
  expect((fetcher.mock.calls[0] as unknown as [string])[0]).toContain('/service-discovery/receipts/exact-key')
})
it('does not turn absent or invalid readback into success',async()=>{
  vi.stubGlobal('fetch',vi.fn(async()=>reply({assessment_id:'assessment',receipt:null})))
  expect(await getServiceDiscoveryReceipt('assessment','target',[80],'key',new AbortController().signal)).toBeNull()
  vi.stubGlobal('fetch',vi.fn(async()=>reply({assessment_id:'other',receipt})))
  await expect(getServiceDiscoveryReceipt('assessment','target',[80,443],'key',new AbortController().signal)).rejects.toThrow()
})
