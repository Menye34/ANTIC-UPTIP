import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import AuthorizedScope from './AuthorizedScope'

const entry = { id: 'scope-ip', value: '192.0.2.1', kind: 'IP address', tcp_ports: [443] }
const response = (body: unknown) => ({ ok: true, json: async () => body })
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

it('uses the existing scope form without asking the analyst for TCP ports', async () => {
  const fetcher = vi.fn().mockResolvedValueOnce(response({ revision: 0, status: 'Draft', can_edit: true, entries: [] }))
    .mockResolvedValueOnce(response({ revision: 1, status: 'Draft', can_edit: true, entries: [{ ...entry, tcp_ports: [] }], changed: entry }))
  vi.stubGlobal('fetch', fetcher)
  render(<AuthorizedScope overview="/analyst/assessments/a" csrfToken="synthetic-csrf" onExpired={vi.fn()} />)
  fireEvent.change(await screen.findByLabelText('Scope entry'), { target: { value: entry.value } })
  expect(screen.queryByLabelText(/Authorized TCP ports/)).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Add to Scope' }))
  expect(await screen.findByText('Scope added')).toBeVisible()
  expect(JSON.parse(fetcher.mock.calls[1][1].body)).toEqual({ revision: 0, value: entry.value })
  expect(fetcher.mock.calls[1][1].headers['X-CSRF-Token']).toBe('synthetic-csrf')
})

it('displays existing port restrictions without silently clearing them during an edit', async () => {
  const fetcher = vi.fn().mockResolvedValueOnce(response({ revision: 2, status: 'Draft', can_edit: true, entries: [entry] }))
    .mockResolvedValueOnce(response({ revision: 3, status: 'Draft', can_edit: true, entries: [entry], changed: entry }))
  vi.stubGlobal('fetch', fetcher)
  render(<AuthorizedScope overview="/analyst/assessments/a" csrfToken="synthetic-csrf" onExpired={vi.fn()} />)
  fireEvent.click(await screen.findByRole('button', { name: /Edit.*192/ }))
  expect(screen.getByText(/TCP 443/)).toBeVisible()
  expect(screen.queryByLabelText(/Authorized TCP ports/)).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }))
  expect(await screen.findByText('Scope updated')).toBeVisible()
  expect(JSON.parse(fetcher.mock.calls[1][1].body)).toEqual({ revision: 2, value: entry.value })
})
