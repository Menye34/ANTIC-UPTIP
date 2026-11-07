import { fireEvent, render, screen, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import AnalystDashboard from './AnalystDashboard'
import type { AnalystDashboardData, AnalystDashboardState } from './AnalystDashboard'

const empty: AnalystDashboardData = {
  assessments: [],
  summary: { activeAssessments: 0, totalFindings: 0, criticalHighFindings: 0, testingResults: 0 },
  activity: [],
  attention: [],
  tools: [],
  severity: { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 },
}

function show(state: AnalystDashboardState) {
  const onSignOut = vi.fn()
  render(<AnalystDashboard state={state} onSignOut={onSignOut} signingOut={false} logoutFailed={false} />)
  return onSignOut
}

describe('Analyst dashboard presentation', () => {
  it('shows the approved empty state for a confirmed empty assessment list', () => {
    show({ status: 'ready', data: empty })
    expect(screen.getByRole('heading', { name: 'No assessments yet' })).toBeVisible()
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
    expect(screen.queryByText('Testing Results')).not.toBeInTheDocument()
    expect(screen.queryByText('Available', { exact: true })).not.toBeInTheDocument()
    expect(within(screen.getByRole('main')).getByRole('link', { name: 'Create Assessment' })).toHaveAttribute('href', '/analyst/assessments/new')
  })

  it('renders supplied assessment activity in the populated sections', () => {
    show({ status: 'ready', data: {
      ...empty,
      assessments: [{ id: 'test-1', name: 'Fixture assessment', stage: 'Testing', work: 'Testing underway',
        ends: '6 Nov', updated: 'Today', action: 'Continue Testing' }],
      summary: { ...empty.summary, activeAssessments: 1 },
      activity: [{ id: 'test-event', title: 'Fixture activity', context: 'Today' }],
    } })
    expect(screen.getByRole('rowheader', { name: 'Fixture assessment' })).toBeVisible()
    expect(screen.getByText('Fixture activity')).toBeVisible()
    expect(screen.getByRole('heading', { name: 'Findings by Severity' })).toBeVisible()
    expect(screen.getByRole('heading', { name: 'Needs your attention' })).toBeVisible()
    expect(screen.queryByText('No assessments yet')).not.toBeInTheDocument()
  })

  it.each([
    ['loading', 'status', 'Loading dashboard data'],
    ['unavailable', 'alert', 'Dashboard data unavailable'],
  ] as const)('keeps %s distinct from confirmed empty activity', (status, role, message) => {
    show({ status })
    expect(screen.getByRole(role)).toHaveTextContent(message)
    expect(screen.queryByText('No assessments yet')).not.toBeInTheDocument()
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
  })

  it('offers Sign Out through the account control', () => {
    const signOut = show({ status: 'unavailable' })
    const account = screen.getByRole('button', { name: 'Account' })
    fireEvent.click(account)
    expect(account).toHaveAttribute('aria-expanded', 'true')
    const button = screen.getByRole('button', { name: 'Sign Out' })
    fireEvent.keyDown(button, { key: 'Escape' })
    expect(account).toHaveFocus()
    expect(account).toHaveAttribute('aria-expanded', 'false')
    fireEvent.click(account)
    fireEvent.click(screen.getByRole('button', { name: 'Sign Out' }))
    expect(signOut).toHaveBeenCalledOnce()
  })
})
