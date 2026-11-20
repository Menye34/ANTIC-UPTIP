import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import FindingsPage from './FindingsPage'
import type { Assessment } from '../services/assessments'
import type { ConsolidatedFinding } from './FindingsPage'

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
  const fetcher = vi.fn(async (url: string) => reply(url.endsWith('/findings') ? { assessment_id: assessment.id, lifecycle_status: 'Finding Review', total: 0, counts: { Critical: 0, High: 0, Medium: 0, Low: 0 }, findings: [] } : assessment))
  vi.stubGlobal('fetch', fetcher)
  renderPage()
  expect(await screen.findByRole('heading', { name: 'Findings' })).toBeVisible()
  expect(await screen.findByText('No findings yet')).toBeVisible()
  expect(screen.getByText(/No consolidated security issues were recorded/)).toBeVisible()
  expect(screen.getAllByText('0')).toHaveLength(5)
  expect(fetcher).toHaveBeenCalledWith('/api/v1/assessments/' + assessment.id,
    expect.objectContaining({ credentials: 'same-origin' }))
  fireEvent.click(screen.getByRole('button', { name: /Add Manual Finding/ }))
  expect(screen.getByRole('dialog', { name: 'Add Manual Finding' })).toBeVisible()
  expect(screen.getByText(/No finding will be saved/)).toBeVisible()
})

it('does not claim Finding Review when the persisted lifecycle is Testing', async () => {
  vi.stubGlobal('fetch', vi.fn(async (url: string) => reply(url.endsWith('/findings') ? { assessment_id: assessment.id, lifecycle_status: 'Testing', total: 0, counts: { Critical: 0, High: 0, Medium: 0, Low: 0 }, findings: [] } : { ...assessment, status: 'Testing' })))
  renderPage()
  expect(await screen.findByText(/Current status: Testing/)).toBeVisible()
  expect(screen.getByText('No findings yet')).toBeVisible()
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

const sample: ConsolidatedFinding = {
  id: 'synthetic-finding', title: 'Content Security Policy (CSP) Header Not Set',
  severity: 'Medium', affectedTarget: 'https://app.example.test', source: 'OWASP ZAP',
  sourceTest: 'Web Application Scan', description: 'The Content-Security-Policy header is missing.',
  impact: 'Content injection exposure', securityControl: 'Content-Security-Policy',
  observedCondition: 'HTTP response does not include the header.',
  detectedIssue: 'Content-Security-Policy header missing',
  remediation: 'Implement and test a Content Security Policy.',
}
it('renders populated F-01 metrics, filters and detail navigation with supplied frontend data', async () => {
  const navigate = vi.fn()
  vi.stubGlobal('fetch', vi.fn(async () => reply(assessment)))
  render(<FindingsPage assessmentId={assessment.id} onExpired={expired} onTesting={back}
    findings={[sample]} onFinding={navigate} />)
  expect(await screen.findByText(sample.title)).toBeVisible()
  expect(screen.getByText('Showing 1 of 1 findings')).toBeVisible()
  fireEvent.change(screen.getByPlaceholderText('Search by finding title or affected target'), { target: { value: 'not present' } })
  expect(screen.getByText('No findings match your filters.')).toBeVisible()
  fireEvent.change(screen.getByPlaceholderText('Search by finding title or affected target'), { target: { value: '' } })
  fireEvent.click(screen.getByRole('button', { name: 'View Details' }))
  expect(navigate).toHaveBeenCalledWith(sample.id)
})
it('renders F-02 details and an unavailable AI state without fabricated advice', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => reply(assessment)))
  render(<FindingsPage assessmentId={assessment.id} onExpired={expired} onTesting={back}
    findings={[sample]} findingId={sample.id} onBack={back} />)
  expect(await screen.findByRole('heading', { name: sample.title })).toBeVisible()
  expect(screen.getByRole('heading', { name: 'Finding Information' })).toBeVisible()
  expect(screen.getByRole('heading', { name: 'Supporting Evidence' })).toBeVisible()
  expect(screen.getByText('Original Tool Output').closest('details')).not.toHaveAttribute('open')
  fireEvent.click(screen.getByRole('button', { name: 'Ask AI About This Finding' }))
  expect(screen.getByRole('dialog', { name: 'AI Assistant' })).toBeVisible()
  fireEvent.click(screen.getByRole('button', { name: 'Suggest a fix' }))
  expect(screen.getByText('AI Assistant is unavailable')).toBeVisible()
  fireEvent.click(screen.getByRole('button', { name: 'Close AI Assistant' }))
  fireEvent.click(screen.getByRole('button', { name: /Back to Findings/ }))
  expect(back).toHaveBeenCalledTimes(1)
})

it('loads real backend findings instead of showing zero by default', async () => {
  const navigate = vi.fn()
  const fetcher = vi.fn(async (url: string) => reply(url.endsWith('/findings')
    ? { assessment_id: assessment.id, lifecycle_status: 'Finding Review', total: 1,
        counts: { Critical: 0, High: 0, Medium: 1, Low: 0 },
        findings: [{ id: sample.id, title: sample.title, severity: sample.severity,
          affected_target: sample.affectedTarget, source: sample.source }] }
    : assessment))
  vi.stubGlobal('fetch', fetcher)
  render(<FindingsPage assessmentId={assessment.id} onExpired={expired}
    onTesting={back} onFinding={navigate} />)
  expect(await screen.findByText(sample.title)).toBeVisible()
  expect(screen.getByText('Showing 1 of 1 findings')).toBeVisible()
  expect(screen.queryByText('No findings yet')).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'View Details' }))
  expect(navigate).toHaveBeenCalledWith(sample.id)
  expect(fetcher).toHaveBeenCalledWith('/api/v1/assessments/' + assessment.id + '/findings',
    expect.objectContaining({ credentials: 'same-origin' }))
})

it('does not show a misleading zero count when findings API fails', async () => {
  vi.stubGlobal('fetch', vi.fn(async (url: string) => reply(
    url.endsWith('/findings') ? {} : assessment,
    url.endsWith('/findings') ? 503 : 200)))
  renderPage()
  expect(await screen.findByRole('alert')).toHaveTextContent('Unable to load verified findings')
  expect(screen.queryByText('No findings yet')).not.toBeInTheDocument()
})

it('loads F-02 details from the assessment-scoped API', async () => {
  const fetcher = vi.fn(async (url: string) => reply(
    url.endsWith('/findings/' + sample.id)
      ? { id: sample.id, title: sample.title, severity: sample.severity,
          affected_target: sample.affectedTarget, source: sample.source,
          source_test: sample.sourceTest, description: sample.description,
          impact: sample.impact, security_control: sample.securityControl,
          observed_condition: sample.observedCondition,
          detected_issue: sample.detectedIssue, remediation: sample.remediation }
      : url.endsWith('/findings')
        ? { assessment_id: assessment.id, lifecycle_status: 'Finding Review', total: 1,
            counts: { Critical: 0, High: 0, Medium: 1, Low: 0 },
            findings: [{ id: sample.id, title: sample.title, severity: sample.severity,
              affected_target: sample.affectedTarget, source: sample.source }] }
        : assessment))
  vi.stubGlobal('fetch', fetcher)
  render(<FindingsPage assessmentId={assessment.id} onExpired={expired}
    onTesting={back} findingId={sample.id} />)
  expect(await screen.findByRole('heading', { name: sample.title })).toBeVisible()
  expect(screen.getByText(sample.remediation)).toBeVisible()
  await waitFor(() => expect(fetcher).toHaveBeenCalledWith(
    '/api/v1/assessments/' + assessment.id + '/findings/' + sample.id,
    expect.objectContaining({ credentials: 'same-origin' })))
})
