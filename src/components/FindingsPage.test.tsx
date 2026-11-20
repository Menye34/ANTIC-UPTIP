import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import FindingsPage from './FindingsPage'
import type { Assessment } from '../services/assessments'

const assessment: Assessment = {
  id: 'synthetic-assessment',
  name: 'Synthetic Network Assessment',
  reference: 'SYN-001',
  status: 'Finding Review',
  description: null,
  start_date: null,
  end_date: null,
  lead_analyst: 'Test Analyst',
  created_by: 'synthetic-analyst',
  created_at: '2026-11-19T10:00:00Z',
}
const reply = (value: unknown, status = 200) => ({ ok: status < 400, status, json: async () => value })
const expired = vi.fn()
const back = vi.fn()
afterEach(() => { cleanup(); vi.unstubAllGlobals(); expired.mockReset(); back.mockReset() })
function renderPage() { return render(<FindingsPage assessmentId={assessment.id} onExpired={expired} onTesting={back} />) }

it('loads an authorized assessment and does not invent candidate findings', async () => {
  const fetcher = vi.fn(async () => reply(assessment))
  vi.stubGlobal('fetch', fetcher)
  renderPage()
  expect(await screen.findByRole('heading', { name: assessment.name })).toBeVisible()
  expect(screen.getByText(/now in Finding Review/)).toBeVisible()
  expect(screen.getByText(/No findings or counts have been assumed/)).toBeVisible()
  expect(fetcher).toHaveBeenCalledWith('/api/v1/assessments/' + assessment.id,
    expect.objectContaining({ credentials: 'same-origin' }))
  fireEvent.click(screen.getByRole('button', { name: 'Back to Testing' }))
  expect(back).toHaveBeenCalledTimes(1)
})

it('does not claim Finding Review when the persisted lifecycle is Testing', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => reply({ ...assessment, status: 'Testing' })))
  renderPage()
  expect(await screen.findByText(/Current status: Testing/)).toBeVisible()
  expect(screen.queryByText(/Testing has been completed/)).not.toBeInTheDocument()
})

it('handles denied access without showing protected assessment details', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => reply({}, 404)))
  renderPage()
  expect(await screen.findByRole('alert')).toHaveTextContent('Assessment unavailable')
  expect(screen.queryByText(assessment.name)).not.toBeInTheDocument()
})

it('ends the session on authentication expiry', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => reply({}, 401)))
  renderPage()
  expect(await screen.findByRole('alert')).toBeVisible()
  expect(expired).toHaveBeenCalledTimes(1)
})
