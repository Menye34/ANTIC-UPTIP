import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import AuthorizedScope from './AuthorizedScope'

const entry = { id: 'scope-ip', value: '192.0.2.1', kind: 'IP address', tcp_ports: [80, 443] }
const response = (body: unknown) => ({ ok: true, json: async () => body })
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

it('saves explicit ports with existing revision and CSRF and displays authoritative readback', async () => {
  const fetcher = vi.fn().mockResolvedValueOnce(response({ revision: 0, status: 'Draft', can_edit: true, entries: [] }))
    .mockResolvedValueOnce(response({ revision: 1, status: 'Draft', can_edit: true, entries: [entry], changed: entry }))
  vi.stubGlobal('fetch', fetcher)
  render(<AuthorizedScope overview="/analyst/assessments/a" csrfToken="synthetic-csrf" onExpired={vi.fn()} />)
  fireEvent.change(await screen.findByLabelText('Scope entry'), { target: { value: entry.value } })
  fireEvent.change(screen.getByLabelText(/Authorized TCP ports/), { target: { value: '80,443' } })
  fireEvent.click(screen.getByRole('button', { name: 'Add to Scope' }))
  expect(await screen.findByText('Scope added')).toBeVisible()
  expect(JSON.parse(fetcher.mock.calls[1][1].body)).toEqual({ revision: 0, value: entry.value, tcp_ports: [80, 443] })
  expect(fetcher.mock.calls[1][1].headers['X-CSRF-Token']).toBe('synthetic-csrf')
  expect(screen.getByText(/TCP 80, 443/)).toBeVisible()
})

it('reloads persisted ports into edit and supports explicit removal', async () => {
  const fetcher = vi.fn().mockResolvedValueOnce(response({ revision: 2, status: 'Draft', can_edit: true, entries: [entry] }))
    .mockResolvedValueOnce(response({ revision: 3, status: 'Draft', can_edit: true, entries: [{ ...entry, tcp_ports: [] }], changed: entry }))
  vi.stubGlobal('fetch', fetcher)
  render(<AuthorizedScope overview="/analyst/assessments/a" csrfToken="synthetic-csrf" onExpired={vi.fn()} />)
  fireEvent.click(await screen.findByRole('button', { name: /Edit.*192/ }))
  expect(screen.getByLabelText(/Authorized TCP ports/)).toHaveValue('80, 443')
  fireEvent.change(screen.getByLabelText(/Authorized TCP ports/), { target: { value: '' } })
  fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }))
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2))
  expect(JSON.parse(fetcher.mock.calls[1][1].body).tcp_ports).toEqual([])
})

it('rejects arbitrary arguments, duplicates and out-of-range ports locally without a mutation', async () => {
  const fetcher = vi.fn().mockResolvedValue(response({ revision: 0, status: 'Draft', can_edit: true, entries: [] }))
  vi.stubGlobal('fetch', fetcher)
  render(<AuthorizedScope overview="/analyst/assessments/a" csrfToken="synthetic-csrf" onExpired={vi.fn()} />)
  fireEvent.change(await screen.findByLabelText('Scope entry'), { target: { value: entry.value } })
  for (const ports of ['80,--script=all', '80,80', '65536', '0']) {
    fireEvent.change(screen.getByLabelText(/Authorized TCP ports/), { target: { value: ports } })
    fireEvent.click(screen.getByRole('button', { name: 'Add to Scope' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('unique TCP ports')
  }
  expect(fetcher).toHaveBeenCalledTimes(1)
})
