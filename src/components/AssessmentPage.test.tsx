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
    expect(screen.getByRole('link', { name: 'Continue Setup' })).toHaveAttribute('href', '/analyst/assessments/' + assessment.id + '/scope')
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

describe('Authorized Scope', () => {
  const path = draftPath + '/scope'
  const entry = { id: 'scope-id', value: '192.168.10.0/24', kind: 'Subnet' }
  const empty = { status: 'Draft', can_edit: true, revision: 0, entries: [] }

  beforeEach(() => {
    // jsdom lacks native dialog methods. The browser owns modal focus trapping.
    Object.defineProperties(HTMLDialogElement.prototype, {
      showModal: { configurable: true, value(this: HTMLDialogElement) { this.open = true } },
      close: { configurable: true, value(this: HTMLDialogElement) { this.open = false } },
    })
  })

  it('shows persisted entries, server duplicate feedback and the empty state after confirmed removal', async () => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce(response(empty))
      .mockResolvedValueOnce(response({ ...empty, revision: 1, entries: [entry], changed: entry }, 201))
      .mockResolvedValueOnce(response({ code: 'duplicate_entry' }, 409))
      .mockResolvedValueOnce(response({ ...empty, revision: 2, changed: entry }))
    vi.stubGlobal('fetch', fetcher)
    renderPage(path)
    expect(await screen.findByText('No authorized scope entries yet')).toBeVisible()
    const nav = screen.getByRole('navigation', { name: 'Analyst workspace' })
    const setup = within(nav).getByText('Setup').closest('details')
    expect(setup).toHaveAttribute('open')
    expect(within(setup!).getByRole('link', { name: 'Authorized Scope' })).toHaveAttribute('aria-current', 'page')
    expect(within(setup!).getByRole('button', { name: 'Assessment Targets' })).toBeDisabled()
    expect(within(nav).getByRole('link', { name: 'Assessment' })).toHaveAttribute('href', draftPath)
    expect(within(nav).getByRole('link', { name: 'Dashboard' })).not.toHaveAttribute('aria-current')
    expect(screen.getByRole('button', { name: 'Continue to Assessment Targets' })).toBeDisabled()
    const input = screen.getByRole('textbox', { name: 'Scope entry' })
    const add = screen.getByRole('button', { name: 'Add to Scope' })
    fireEvent.click(add)
    expect(input).toHaveAccessibleDescription('Enter a scope entry.')
    expect(fetcher).toHaveBeenCalledTimes(1)
    fireEvent.change(input, { target: { value: entry.value } })
    fireEvent.click(add)
    expect(await screen.findByText('Scope added')).toBeVisible()
    expect(screen.getByRole('cell', { name: entry.value })).toBeVisible()
    expect(fetcher.mock.calls[1][0]).toBe(api + '/' + assessment.id + '/scope')
    expect(JSON.parse(fetcher.mock.calls[1][1].body)).toEqual({ value: entry.value, revision: 0 })
    fireEvent.change(input, { target: { value: entry.value } })
    fireEvent.click(add)
    expect(await screen.findByText('This scope entry already exists. Enter a different value.')).toBeVisible()
    expect(input).toHaveAttribute('aria-invalid', 'true')
    fireEvent.click(screen.getByRole('button', { name: /^Remove/ }))
    expect(screen.getByRole('dialog')).toHaveAccessibleName('Remove authorized scope?')
    fireEvent(screen.getByRole('dialog'), new Event('cancel', { cancelable: true }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(fetcher).toHaveBeenCalledTimes(3)
    fireEvent.click(screen.getByRole('button', { name: /^Remove/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Confirm Removal' }))
    expect(await screen.findByText('No authorized scope entries yet')).toBeVisible()
    expect(JSON.parse(fetcher.mock.calls[3][1].body)).toEqual({ confirmed: true, revision: 1 })
  })

  it('prefills the edit field and reloads the authoritative list after a stale write', async () => {
    const updated = { ...entry, value: '192.168.30.0/24' }
    const fetcher = vi.fn()
      .mockResolvedValueOnce(response({ ...empty, entries: [entry] }))
      .mockResolvedValueOnce(response({ code: 'stale_revision' }, 409))
      .mockResolvedValueOnce(response({ ...empty, revision: 1, entries: [updated] }))
    vi.stubGlobal('fetch', fetcher)
    renderPage(path)
    fireEvent.click(await screen.findByRole('button', { name: /^Edit/ }))
    const input = screen.getByRole('textbox', { name: 'Edit scope entry' })
    expect(input).toHaveValue(entry.value)
    expect(input).toHaveFocus()
    fireEvent.change(input, { target: { value: '192.168.20.0/24' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Authorized scope changed.')
    expect(fetcher.mock.calls[1][1].method).toBe('PATCH')
    fireEvent.click(screen.getByRole('button', { name: 'Reload entries' }))
    expect(await screen.findByRole('cell', { name: updated.value })).toBeVisible()
  })

  it('preserves a same-user view and ignores pending mutations after account switching', async () => {
    window.history.replaceState(null, '', path)
    let userId = analystId
    let reads = 0
    let finish!: (value: ReturnType<typeof response>) => void
    vi.stubGlobal('fetch', vi.fn(async (url: string, options?: RequestInit) => {
      if (url.endsWith('/scope')) {
        if (options?.method === 'POST') return new Promise(resolve => { finish = resolve })
        reads += 1
        return userId === analystId ? response(empty) : response({}, 404)
      }
      return response({ state: 'authenticated', role: 'Security Analyst', username: 'analyst',
        user_id: userId, csrf_token: 'test-csrf' })
    }))
    render(<App />)
    const field = await screen.findByRole('textbox', { name: 'Scope entry' })
    fireEvent.change(field, { target: { value: entry.value } })
    await act(async () => fireEvent.focus(window))
    expect(reads).toBe(1)
    expect(field).toHaveValue(entry.value)
    fireEvent.click(screen.getByRole('button', { name: 'Add to Scope' }))
    userId = 'analyst-b-id'
    await act(async () => fireEvent.focus(window))
    expect(await screen.findByRole('alert')).toHaveTextContent('Unable to load authorized scope')
    await act(async () => finish(response({ ...empty, revision: 1, entries: [entry], changed: entry }, 201)))
    expect(screen.queryByText(entry.value)).not.toBeInTheDocument()
    expect(screen.queryByRole('textbox', { name: 'Scope entry' })).not.toBeInTheDocument()
  })
})
