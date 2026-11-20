import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import Drawer from './ExecutionDetailsDrawer'
import { getExecutionDetails, getOriginalEvidence } from '../services/testing'
import { AssessmentStartError } from '../services/assessmentStart'
import { executionDetails, assessmentId } from '../test-fixtures/testing'
import type { ExecutionDetails } from '../services/testing'
vi.mock('../services/testing', () => ({ getExecutionDetails: vi.fn(), getOriginalEvidence: vi.fn() }))
const details = vi.mocked(getExecutionDetails), original = vi.mocked(getOriginalEvidence)
const initialShow = Object.getOwnPropertyDescriptor(HTMLDialogElement.prototype, 'showModal')
const initialClose = Object.getOwnPropertyDescriptor(HTMLDialogElement.prototype, 'close')
const expired = vi.fn(), closed = vi.fn()
function state(completed = false): ExecutionDetails {
  return { ...executionDetails(), status: completed ? 'Completed' : 'Running',
    attempts: [{ id: 'a', attempt_number: 1, status: completed ? 'Succeeded' : 'Running', reason_code: null,
      started_at: '2026-11-20T10:00:00Z', finished_at: completed ? '2026-11-20T10:01:00Z' : null,
      exit_code: completed ? 0 : null, recovery_reason: null }],
    processing: [{ id: 'p', status: completed ? 'Succeeded' : 'Processing', processor: 'nmap', version: '1', error_code: null,
      observation_count: 0, partial: false }] }
}
async function mount() {
  let view: ReturnType<typeof render>
  await act(async () => { view = render(<Drawer assessmentId={assessmentId} executionId="synthetic-execution-0" onClose={closed} onExpired={expired} />) })
  return view!
}
beforeEach(() => {
  vi.useFakeTimers(); details.mockReset(); original.mockReset(); expired.mockReset(); closed.mockReset()
  Object.defineProperty(HTMLDialogElement.prototype, 'showModal', { configurable: true, value(this: HTMLDialogElement) { this.open = true } })
  Object.defineProperty(HTMLDialogElement.prototype, 'close', { configurable: true, value(this: HTMLDialogElement) { this.open = false } })
})
afterEach(() => {
  cleanup(); vi.useRealTimers()
  if (initialShow) Object.defineProperty(HTMLDialogElement.prototype, 'showModal', initialShow)
  else Reflect.deleteProperty(HTMLDialogElement.prototype, 'showModal')
  if (initialClose) Object.defineProperty(HTMLDialogElement.prototype, 'close', initialClose)
  else Reflect.deleteProperty(HTMLDialogElement.prototype, 'close')
})

it('polls sequentially, preserves disclosures, scroll and focus, and stops at stable completion', async () => {
  details.mockResolvedValueOnce(state()).mockResolvedValueOnce(state(true))
  await mount()
  const technical = screen.getByText('Technical Details').closest('details')!
  technical.open = true
  const summary = within(technical).getByText('Technical Details'); summary.focus()
  const body = technical.closest('.testing-review-body')!; body.scrollTop = 83
  await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
  expect(details).toHaveBeenCalledTimes(2)
  expect(technical).toHaveAttribute('open')
  expect(body.scrollTop).toBe(83); expect(summary).toHaveFocus()
  await act(async () => { await vi.advanceTimersByTimeAsync(15000) })
  expect(details).toHaveBeenCalledTimes(2)
})

it('does not overlap pending requests and keeps uncertain RecoveryRequired work refreshing', async () => {
  let resolve!: (data: ExecutionDetails) => void
  details.mockImplementationOnce(() => new Promise(r => { resolve = r }))
  details.mockResolvedValue({ ...state(), attempts: [{ ...state().attempts[0], status: 'RecoveryRequired' }] })
  await mount()
  await act(async () => { await vi.advanceTimersByTimeAsync(15000) })
  expect(details).toHaveBeenCalledTimes(1)
  await act(async () => { resolve(state()) })
  await act(async () => { await vi.advanceTimersByTimeAsync(10000) })
  expect(details).toHaveBeenCalledTimes(3)
  expect(screen.getByText('Technical Details').closest('details')).not.toHaveAttribute('open')
})

it('keeps cached results explicitly unverified on transient errors and retries without resetting disclosures', async () => {
  details.mockResolvedValueOnce(state()).mockRejectedValueOnce(new Error('transient')).mockResolvedValue(state(true))
  await mount()
  const technical = screen.getByText('Technical Details').closest('details')!; technical.open = true
  await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
  expect(screen.getByRole('alert')).toHaveTextContent('not verified as current')
  expect(technical).toHaveAttribute('open')
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Retry' })) })
  expect(technical).toHaveAttribute('open')
  expect(screen.queryByRole('alert')).not.toBeInTheDocument()
})

it('clears protected results and stops polling on access denial', async () => {
  details.mockResolvedValueOnce(state()).mockRejectedValueOnce(new AssessmentStartError(403))
  await mount()
  await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
  expect(screen.getByRole('alert')).toHaveTextContent('Execution unavailable')
  expect(screen.queryByText('Network Discovery')).not.toBeInTheDocument()
  await act(async () => { await vi.advanceTimersByTimeAsync(15000) })
  expect(details).toHaveBeenCalledTimes(2)
})

it('aborts pending detail requests on close and rejects late responses', async () => {
  let resolve!: (data: ExecutionDetails) => void
  details.mockImplementation(() => new Promise(r => { resolve = r }))
  const view = await mount(); const signal = details.mock.calls[0][2]
  view.unmount(); expect(signal.aborted).toBe(true)
  await act(async () => { resolve(state(true)); await vi.advanceTimersByTimeAsync(5000) })
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(details).toHaveBeenCalledTimes(1)
})

it('lazy loads original output as escaped text and keeps Technical Details collapsed', async () => {
  const text = '<script>alert("not executed")</script>'
  const value = state(true)
  const evidence = { id: 'e', format: 'nmap-xml', size_bytes: text.length, partial: false,
    collected_at: '2026-11-20T10:01:00Z', sha256: 'a'.repeat(64) }
  value.evidence = [evidence]; details.mockResolvedValue(value)
  original.mockResolvedValue({ ...evidence, assessment_id: assessmentId, execution_id: value.id, evidence_id: 'e', content: text })
  await mount()
  expect(original).not.toHaveBeenCalled()
  const disclosure = screen.getByText('Original Tool Output').closest('details')!
  await act(async () => { disclosure.open = true; fireEvent(disclosure, new Event('toggle')) })
  expect(original).toHaveBeenCalledTimes(1)
  const output = screen.getByText(text)
  expect(output.tagName).toBe('PRE'); expect(output.querySelector('script')).toBeNull()
  expect(screen.getByText('Technical Details').closest('details')).not.toHaveAttribute('open')
})

it('renders the Figma service table from recorded facts without inventing versions', async () => {
  const value = state(true)
  value.observations = [{ id: 'o', type: 'service_discovery', evidence_id: 'e', partial: false,
    data: { address: value.target, port: 443, state: 'open', transport: 'tcp', service: 'https' } }]
  details.mockResolvedValue(value); await mount()
  expect(screen.getByRole('dialog')).toHaveClass('testing-review-dialog')
  const table = screen.getByRole('table', { name: 'Discovered ports and services' })
  for (const label of ['Port', 'Service', 'Version', '443/tcp', 'HTTPS', 'Not identified']) expect(within(table).getByText(label)).toBeVisible()
})
