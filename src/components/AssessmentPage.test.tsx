import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from '../App'
import { clearKnownSession } from '../services/auth'
import AssessmentPage from './AssessmentPage'
import type { Assessment } from '../services/assessments'

const assessment: Assessment = {
  id: 'b1c9d21b-e71b-4be8-b980-a565f256872e',
  reference: 'ASM-2026-001',
  status: 'Draft',
  name: 'Branch office review',
  description: 'Network review',
  start_date: '2026-11-07',
  end_date: null,
  lead_analyst: 'analyst-review',
  created_by: 'analyst-review',
  created_at: '2026-11-07T10:00:00Z',
}
const draftPath = '/analyst/assessments/' + assessment.id
const createPath = '/analyst/assessments/new'
const analystId = 'analyst-a-id'
const api = '/api/v1/assessments'
const response = (body: unknown, status = 200) => ({ ok: status < 400, status, json: async () => body })

function renderPage(path = createPath, showCreated = false) {
  const navigate = vi.fn()
  const onExpired = vi.fn()
  render(<AssessmentPage userId={analystId} path={path} showCreated={showCreated} username="analyst-review" csrfToken="test-csrf"
    navigate={navigate} onExpired={onExpired} signingOut={false} logoutFailed={false} onSignOut={vi.fn()} />)
  return { navigate, onExpired }
}

function nameField() {
  return screen.getByRole('textbox', { name: /assessment name/i })
}

function submit() {
  fireEvent.click(screen.getByRole('button', { name: 'Create Assessment' }))
}

beforeEach(() => {
  window.history.replaceState(null, '', '/')
  clearKnownSession()
})
afterEach(() => {
  cleanup()
  clearKnownSession()
  vi.unstubAllGlobals()
})

describe('Create Assessment', () => {
  it('shows the default form and server identity, and focuses the name field', () => {
    renderPage()
    expect(screen.getByRole('heading', { name: 'Create Assessment' })).toBeVisible()
    expect(nameField()).toHaveValue('')
    expect(screen.getByLabelText('Start date')).not.toBeRequired()
    expect(screen.getByLabelText('End date')).not.toBeRequired()
    expect(screen.queryByRole('textbox', { name: 'Lead analyst' })).not.toBeInTheDocument()
    expect(within(nameField().closest('form')!).getByText('analyst-review')).toBeVisible()
    act(() => nameField().focus())
    expect(nameField()).toHaveFocus()
  })

  it('rejects a blank name and reversed dates before sending a request', () => {
    const fetcher = vi.fn()
    vi.stubGlobal('fetch', fetcher)
    renderPage()
    fireEvent.change(nameField(), { target: { value: '  ' } })
    submit()
    expect(nameField()).toHaveAttribute('aria-invalid', 'true')
    expect(screen.getByText('Enter an assessment name.')).toBeVisible()
    fireEvent.change(nameField(), { target: { value: 'Network review' } })
    fireEvent.change(screen.getByLabelText('Start date'), { target: { value: '2026-11-08' } })
    fireEvent.change(screen.getByLabelText('End date'), { target: { value: '2026-11-07' } })
    submit()
    const end = screen.getByLabelText('End date')
    expect(end).toHaveAttribute('aria-invalid', 'true')
    expect(end).toHaveAccessibleDescription('End date must be on or after the start date.')
    expect(end).toHaveFocus()
    expect(screen.getByLabelText('Start date')).toHaveAttribute('aria-invalid', 'false')
    expect(fetcher).not.toHaveBeenCalled()
  })

  it('associates an invalid start date with the start input', () => {
    vi.stubGlobal('fetch', vi.fn())
    renderPage()
    fireEvent.change(nameField(), { target: { value: 'Draft' } })
    const start = screen.getByLabelText('Start date')
    fireEvent.change(start, { target: { value: '10000-01-01' } })
    submit()
    expect(start).toHaveAttribute('aria-invalid', 'true')
    expect(start).toHaveAccessibleDescription('Enter a valid testing date.')
    expect(start).toHaveFocus()
    expect(screen.getByLabelText('End date')).toHaveAttribute('aria-invalid', 'false')
  })

  it('cancels to the analyst dashboard without saving', () => {
    const fetcher = vi.fn()
    vi.stubGlobal('fetch', fetcher)
    const { navigate } = renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(navigate).toHaveBeenCalledWith('/analyst/dashboard')
    expect(fetcher).not.toHaveBeenCalled()
  })

  it('trims the name, accepts missing optional fields, and blocks duplicate in-flight submits', async () => {
    let finish!: (value: ReturnType<typeof response>) => void
    const fetcher = vi.fn(() => new Promise(resolve => { finish = resolve }))
    vi.stubGlobal('fetch', fetcher)
    const { navigate } = renderPage()
    fireEvent.change(nameField(), { target: { value: '  Branch office review  ' } })
    submit()
    fireEvent.submit(nameField().closest('form')!)
    expect(fetcher).toHaveBeenCalledOnce()
    expect(screen.getByRole('button', { name: 'Saving…' })).toBeDisabled()
    expect(fetcher).toHaveBeenCalledWith(api, expect.objectContaining({
      method: 'POST', credentials: 'same-origin',
      headers: expect.objectContaining({ 'X-CSRF-Token': 'test-csrf', 'Idempotency-Key': expect.any(String) }),
      body: JSON.stringify({ name: assessment.name, description: null, start_date: null, end_date: null }),
    }))
    await act(async () => finish(response(assessment, 201)))
    expect(navigate).toHaveBeenCalledWith(draftPath, analystId)
  })

  it('preserves input on failure and handles an expired session', async () => {
    const fetcher = vi.fn().mockResolvedValueOnce(response({}, 503)).mockResolvedValueOnce(response({}, 401))
    vi.stubGlobal('fetch', fetcher)
    const { navigate, onExpired } = renderPage()
    fireEvent.change(nameField(), { target: { value: 'Network review' } })
    submit()
    expect(await screen.findByRole('alert')).toHaveTextContent('save could not be confirmed')
    expect(nameField()).toHaveValue('Network review')
    expect(navigate).not.toHaveBeenCalled()
    await act(async () => submit())
    expect(onExpired).toHaveBeenCalledOnce()
    const first = fetcher.mock.calls[0] as unknown as [string, RequestInit]
    const second = fetcher.mock.calls[1] as unknown as [string, RequestInit]
    const key = new Headers(first[1].headers).get('Idempotency-Key')
    expect(key).toBeTruthy()
    expect(new Headers(second[1].headers).get('Idempotency-Key')).toBe(key)
  })
})

describe('Draft Assessment Overview', () => {
  it('shows stored details and a dismissible confirmation after creation', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(assessment)))
    renderPage(draftPath, true)
    expect(await screen.findByRole('heading', { name: assessment.name })).toBeVisible()
    expect(screen.getByText('Reference: ' + assessment.reference)).toBeVisible()
    expect(screen.getByText(assessment.description!)).toBeVisible()
    expect(screen.getByText('0 targets')).toBeVisible()
    expect(screen.getByText('No authorized scope defined')).toBeVisible()
    expect(screen.getByRole('button', { name: 'Continue Setup' })).toBeDisabled()
    expect(screen.getByRole('status')).toHaveTextContent('Assessment created')
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss confirmation' }))
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
  })

  it('loads a direct visit without displaying a creation confirmation', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(assessment)))
    renderPage(draftPath)
    await screen.findByRole('heading', { name: assessment.name })
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
  })

  it('shows the same unavailable message for an inaccessible record', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({}, 404)))
    renderPage(draftPath)
    expect(await screen.findByRole('alert')).toHaveTextContent('Assessment unavailable')
  })
})

describe('Protected assessment routes', () => {
  it.each([
    ['unauthenticated', 401, null, 'Sign in to UPTIP'],
    ['authenticated', 200, 'Technical Administrator', 'Administrator Dashboard'],
  ] as const)('gates the Create Assessment route for %s %s %s', async (state, status, role, heading) => {
    window.history.replaceState(null, '', createPath)
    const fetcher = vi.fn<(url: string) => Promise<ReturnType<typeof response>>>()
      .mockResolvedValue(response({ state, role, csrf_token: 'test-csrf' }, status))
    vi.stubGlobal('fetch', fetcher)
    render(<App />)
    expect(await screen.findByRole('heading', { name: heading })).toBeVisible()
    expect(screen.queryByRole('heading', { name: 'Create Assessment' })).not.toBeInTheDocument()
    expect(fetcher.mock.calls.every(([url]) => url === '/api/v1/auth/session')).toBe(true)
  })

  it('routes the authenticated analyst from creation to the persisted overview', async () => {
    window.history.replaceState(null, '', createPath)
    const fetcher = vi.fn(async (url: string) => {
      if (url === api) return response(assessment, 201)
      if (url === api + '/' + assessment.id) return response(assessment)
      return response({ state: 'authenticated', role: 'Security Analyst', username: 'analyst-review', user_id: analystId, csrf_token: 'test-csrf' })
    })
    vi.stubGlobal('fetch', fetcher)
    render(<App />)
    await screen.findByRole('heading', { name: 'Create Assessment' })
    fireEvent.change(nameField(), { target: { value: assessment.name } })
    submit()
    expect(await screen.findByRole('heading', { name: assessment.name })).toBeVisible()
    expect(window.location.pathname).toBe(draftPath)
    expect(screen.getByRole('status')).toHaveTextContent('Assessment created')
  })
})


describe('Assessment account switches', () => {
  it('keeps an overview on same-user refresh and clears it when another analyst signs in', async () => {
    window.history.replaceState(null, '', draftPath)
    let userId = analystId
    let reads = 0
    let allowOther = false
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      if (url === api + '/' + assessment.id) {
        reads += 1
        return userId === analystId || allowOther ? response(assessment) : response({}, 404)
      }
      return response({ state: 'authenticated', role: 'Security Analyst', username: 'same-display-name',
        user_id: userId, csrf_token: 'test-csrf' })
    }))
    render(<App />)
    await screen.findByRole('heading', { name: assessment.name })
    await act(async () => fireEvent.focus(window))
    expect(reads).toBe(1)
    expect(screen.getByRole('heading', { name: assessment.name })).toBeVisible()
    userId = 'analyst-b-id'
    await act(async () => fireEvent.focus(window))
    expect(screen.queryByRole('heading', { name: assessment.name })).not.toBeInTheDocument()
    expect(await screen.findByRole('alert')).toHaveTextContent('Assessment unavailable')
    expect(reads).toBe(2)

    cleanup()
    allowOther = true
    render(<App />)
    expect(await screen.findByRole('heading', { name: assessment.name })).toBeVisible()
  })

  it('ignores a late overview response from the previous analyst', async () => {
    window.history.replaceState(null, '', draftPath)
    let userId = analystId
    let finish!: (value: ReturnType<typeof response>) => void
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      if (url === api + '/' + assessment.id) {
        if (userId !== analystId) return response({}, 404)
        return new Promise(resolve => { finish = resolve })
      }
      return response({ state: 'authenticated', role: 'Security Analyst', username: 'analyst',
        user_id: userId, csrf_token: 'test-csrf' })
    }))
    render(<App />)
    await screen.findByText('Loading assessment…')
    userId = 'analyst-b-id'
    await act(async () => fireEvent.focus(window))
    expect(await screen.findByRole('alert')).toHaveTextContent('Assessment unavailable')
    await act(async () => finish(response(assessment)))
    expect(screen.queryByRole('heading', { name: assessment.name })).not.toBeInTheDocument()
  })
})
