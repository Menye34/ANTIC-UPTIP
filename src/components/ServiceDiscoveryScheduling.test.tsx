import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import ServiceDiscoveryScheduling from './ServiceDiscoveryScheduling'
import { testingData } from '../test-fixtures/testing'
const reply=(value:unknown,status=200)=>({ok:status<400,status,json:async()=>value})
const receipt={execution_id:'service-execution',assessment_id:'synthetic-assessment',target_id:'synthetic-target-0',ports:[80,443],consent_digest:'a'.repeat(64),expires_at:'2026-11-20T10:00:00Z',status:'Queued',execution_authorized:false}
const changed=vi.fn(),expired=vi.fn()
const show=Object.getOwnPropertyDescriptor(HTMLDialogElement.prototype,'showModal'),close=Object.getOwnPropertyDescriptor(HTMLDialogElement.prototype,'close')
beforeEach(()=>{
 changed.mockReset();expired.mockReset()
 Object.defineProperty(HTMLDialogElement.prototype,'showModal',{configurable:true,value(this:HTMLDialogElement){this.open=true}})
 Object.defineProperty(HTMLDialogElement.prototype,'close',{configurable:true,value(this:HTMLDialogElement){this.open=false}})
})
afterEach(()=>{
 cleanup();vi.unstubAllGlobals()
 for(const [name,definition] of [['showModal',show],['close',close]] as const){if(definition)Object.defineProperty(HTMLDialogElement.prototype,name,definition);else Reflect.deleteProperty(HTMLDialogElement.prototype,name)}
})
function props(){return {data:{...testingData(['Completed']),can_schedule_service_discovery:true},visible:true,available:true,csrfToken:'csrf',onChanged:changed,onExpired:expired}}
function fill(){
 fireEvent.click(screen.getByRole('button',{name:'Schedule Service Discovery'}))
 fireEvent.change(screen.getByLabelText('Authorized target'),{target:{value:'synthetic-target-0'}})
 fireEvent.change(screen.getByLabelText('Authorized TCP ports'),{target:{value:'443,80'}})
 fireEvent.click(screen.getByRole('checkbox'))
}
it.each(['missing','assigned','csrf','stale'])("fails closed for %s permission",mode=>{
 const p=props();if(mode==='missing')delete p.data.can_schedule_service_discovery
 if(mode==='assigned')p.data.can_schedule_service_discovery=false
 if(mode==='csrf')p.csrfToken='';if(mode==='stale')p.available=false
 render(<ServiceDiscoveryScheduling {...p}/>);expect(screen.getByRole('button',{name:'Schedule Service Discovery'})).toBeDisabled()
})
it('requires explicit target, ports and renewed consent after editing',()=>{
 const fetcher=vi.fn();vi.stubGlobal('fetch',fetcher);render(<ServiceDiscoveryScheduling {...props()}/>);
 fireEvent.click(screen.getByRole('button',{name:'Schedule Service Discovery'}))
 expect(screen.getByRole('button',{name:'Confirm and Queue'})).toBeDisabled()
 expect(screen.getByLabelText('Authorized TCP ports')).toHaveValue('')
 fireEvent.change(screen.getByLabelText('Authorized target'),{target:{value:'synthetic-target-0'}})
 fireEvent.change(screen.getByLabelText('Authorized TCP ports'),{target:{value:'80,443'}})
 fireEvent.click(screen.getByRole('checkbox'));expect(screen.getByRole('button',{name:'Confirm and Queue'})).toBeEnabled()
 fireEvent.change(screen.getByLabelText('Authorized TCP ports'),{target:{value:'22'}})
 expect(screen.getByRole('checkbox')).not.toBeChecked();expect(fetcher).not.toHaveBeenCalled()
})
it('queues once, guards rapid clicks, and reports historical scheduling only',async()=>{
 let done!:(v:ReturnType<typeof reply>)=>void
 const fetcher=vi.fn(()=>new Promise(resolve=>{done=resolve}));vi.stubGlobal('fetch',fetcher)
 render(<ServiceDiscoveryScheduling {...props()}/>);fill()
 fireEvent.click(screen.getByRole('button',{name:'Confirm and Queue'}))
 fireEvent.submit(screen.getByRole('button',{name:'Scheduling…'}).closest('form')!)
 expect(fetcher).toHaveBeenCalledTimes(1)
 await act(async()=>done(reply(receipt)))
 expect(screen.getByRole('status')).toHaveTextContent('scheduled does not mean running or completed')
 expect(changed).toHaveBeenCalledTimes(1);expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
})
it('cancel and Escape never schedule and restore focus',()=>{
 const fetcher=vi.fn();vi.stubGlobal('fetch',fetcher);render(<ServiceDiscoveryScheduling {...props()}/>);fill()
 fireEvent(screen.getByRole('dialog'),new Event('cancel',{cancelable:true}))
 expect(fetcher).not.toHaveBeenCalled();expect(screen.getByRole('button',{name:'Schedule Service Discovery'})).toHaveFocus()
})
it('invalidates an open confirmation when permission changes',()=>{
 const p=props(), view=render(<ServiceDiscoveryScheduling {...p}/>);fill()
 view.rerender(<ServiceDiscoveryScheduling {...p} data={{...p.data,can_schedule_service_discovery:false}}/>)
 expect(screen.getByRole('button',{name:'Confirm and Queue'})).toBeDisabled()
})
it('keeps uncertain outcomes across hiding, verifies by GET, and never retries POST',async()=>{
 const fetcher=vi.fn(async(_url:string,options?:RequestInit)=>{
  if(options?.method==='POST')throw new TypeError('lost response')
  return reply({assessment_id:'synthetic-assessment',receipt:null})
 });vi.stubGlobal('fetch',fetcher)
 const p=props(),view=render(<ServiceDiscoveryScheduling {...p}/>);fill()
 fireEvent.click(screen.getByRole('button',{name:'Confirm and Queue'}))
 await screen.findAllByText(/scheduling outcome is unverified/)
 fireEvent.click(screen.getByRole('button',{name:'Close'}))
 view.rerender(<ServiceDiscoveryScheduling {...p} visible={false}/>)
 view.rerender(<ServiceDiscoveryScheduling {...p}/>)
 fireEvent.click(screen.getByRole('button',{name:'Check scheduling status'}))
 expect(await screen.findByText(/No saved receipt is visible/)).toBeVisible()
 expect(fetcher.mock.calls.filter(([,options])=>options?.method==='POST')).toHaveLength(1)
 fetcher.mockImplementation(async()=>reply({assessment_id:'synthetic-assessment',receipt}))
 fireEvent.click(screen.getByRole('button',{name:'Check scheduling status'}))
 expect(await screen.findByRole('status')).toHaveTextContent('scheduling was confirmed')
})
it('handles known refusal and session expiry without inventing success',async()=>{
 vi.stubGlobal('fetch',vi.fn(async()=>reply({},401)))
 render(<ServiceDiscoveryScheduling {...props()}/>);fill();fireEvent.click(screen.getByRole('button',{name:'Confirm and Queue'}))
 expect(await screen.findByText('Your session has ended. Sign in again to continue.')).toBeVisible()
 expect(expired).toHaveBeenCalledOnce();expect(screen.queryByRole('status')).not.toBeInTheDocument()
})
it('aborts on unmount and ignores late success',async()=>{
 let done!:(v:ReturnType<typeof reply>)=>void
 const fetcher=vi.fn((url:string,options:RequestInit)=>{expect(url).toContain('service-discovery');expect(options.method).toBe('POST');return new Promise(resolve=>{done=resolve})});vi.stubGlobal('fetch',fetcher)
 const view=render(<ServiceDiscoveryScheduling {...props()}/>);fill();fireEvent.click(screen.getByRole('button',{name:'Confirm and Queue'}))
 const signal=fetcher.mock.calls[0][1].signal!;view.unmount();expect(signal.aborted).toBe(true)
 await act(async()=>done(reply(receipt)));expect(changed).not.toHaveBeenCalled()
})
it('excludes already-scheduled targets regardless of their current execution status',()=>{
 const p=props();p.data.executions.push({...p.data.executions[0],id:'service',profile_id:'service-discovery',profile_version:1,status:'Failed'})
 render(<ServiceDiscoveryScheduling {...p}/>);expect(screen.getByRole('button',{name:'Schedule Service Discovery'})).toBeDisabled()
})
