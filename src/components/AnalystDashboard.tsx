import { useRef, useState } from 'react'
import bell from '../assets/analyst/NotificationBell.svg'
import shield from '../assets/analyst/ApprovedLinkedNodesShield.svg'
import dashboard from '../assets/analyst/LayoutDashboard.svg'
import scope from '../assets/analyst/ShieldCheck.svg'
import document from '../assets/analyst/FileText.svg'
import available from '../assets/analyst/Available.svg'
import disabled from '../assets/analyst/Disabled.svg'
import connectionProblem from '../assets/analyst/ConnectionProblem.svg'
import './AnalystDashboard.css'

const severities = ['Critical', 'High', 'Medium', 'Low', 'Informational'] as const

export interface AnalystDashboardData {
  displayName?: string
  initials?: string
  assessments: { id: string; name: string; stage: string; work: string; ends: string; updated: string; action: string }[]
  summary: { activeAssessments: number; totalFindings: number; criticalHighFindings: number; testingResults: number }
  activity: { id: string; title: string; context: string }[]
  attention: { id: string; title: string; context: string; action: string }[]
  tools: { name: string; description: string; status: 'Available' | 'Disabled' | 'Connection problem' }[]
  severity: Record<(typeof severities)[number], number>
}

export type AnalystDashboardState =
  | { status: 'loading' | 'unavailable' }
  | { status: 'ready'; data: AnalystDashboardData }

const toolStatusIcons = { Available: available, Disabled: disabled, 'Connection problem': connectionProblem }

const navigation = [
  ['Dashboard', dashboard], ['Assessments', scope], ['Scope & Targets', scope],
  ['Testing', document], ['Findings', document], ['Report', document], ['Audit Log', document],
]

function UnavailableAction({ children }: { children: string }) {
  return <button type="button" className="analyst-link" disabled title="Unavailable in this release">{children}</button>
}

function CreateAssessment({ prominent = false }: { prominent?: boolean }) {
  return <button type="button" className="analyst-create" disabled title="Assessment creation is unavailable in this release">
    {prominent ? '+ Create Assessment' : 'Create Assessment'}
  </button>
}

function Tools({ tools }: { tools: AnalystDashboardData['tools'] }) {
  return <section className="analyst-card">
    <h2>Available tools</h2>
    {tools.length ? tools.map(tool => <div className="analyst-tool" key={tool.name}>
      <div>{tool.name}<small>{tool.description}</small></div>
      <span className="analyst-tool-status" data-status={tool.status}><img src={toolStatusIcons[tool.status]} alt="" />{tool.status}</span>
    </div>) : <p>Tool status unavailable.</p>}
    <small>Managed by your administrator.</small>
  </section>
}

function Activity({ activity }: { activity: AnalystDashboardData['activity'] }) {
  return <section className="analyst-card">
    <h2>Recent Activity</h2>
    {activity.length ? <ul className="analyst-activity">{activity.map(item => <li key={item.id}>
      <span>{item.title}</span><small>{item.context}</small>
    </li>)}</ul> : <p>No activity yet</p>}
    <UnavailableAction>View Audit Log</UnavailableAction>
  </section>
}

function EmptyDashboard({ data }: { data: AnalystDashboardData }) {
  return <div className="analyst-columns">
    <section className="analyst-card analyst-assessments">
      <h2>My Assessments</h2>
      <div className="analyst-empty">
        <h3>No assessments yet</h3>
        <p>Create an assessment to define the authorized scope and begin security testing.</p>
        <CreateAssessment />
      </div>
    </section>
    <div className="analyst-stack">
      <section className="analyst-card">
        <h2>How it works</h2>
        <ol className="analyst-steps">
          <li>Create an assessment</li><li>Define the authorized scope and targets</li>
          <li>Run testing</li><li>Explore security findings</li>
        </ol>
      </section>
      <Tools tools={data.tools} />
      <Activity activity={data.activity} />
    </div>
  </div>
}

function PopulatedDashboard({ data }: { data: AnalystDashboardData }) {
  const metrics = [
    ['Active Assessments', data.summary.activeAssessments, 'In testing or findings available'],
    ['Total Findings', data.summary.totalFindings, 'Consolidated security findings'],
    ['Critical & High Findings', data.summary.criticalHighFindings, 'By severity'],
    ['Testing Results', data.summary.testingResults, 'Observations across active assessments'],
  ] as const
  const maximum = Math.max(1, ...severities.map(severity => data.severity[severity]))
  return <>
    <div className="analyst-metrics">{metrics.map(([label, value, description]) =>
      <section className="analyst-card" key={label}><h2>{label}</h2><strong>{value}</strong><small>{description}</small></section>
    )}</div>
    <div className="analyst-columns">
      <div className="analyst-stack">
        <section className="analyst-card analyst-assessments">
          <h2>My Assessments</h2>
          <div className="analyst-table-scroll" tabIndex={0} aria-label="My Assessments table">
            <table>
              <thead><tr>{['Assessment', 'Stage', 'Current work', 'Ends', 'Updated', 'Action'].map(label => <th key={label} scope="col">{label}</th>)}</tr></thead>
              <tbody>{data.assessments.map(row => <tr key={row.id}>
                <th scope="row">{row.name}</th><td><span className="analyst-stage" data-stage={row.stage}>{row.stage}</span></td>
                <td>{row.work}</td><td>{row.ends}</td><td>{row.updated}</td><td><UnavailableAction>{row.action}</UnavailableAction></td>
              </tr>)}</tbody>
            </table>
          </div>
          <UnavailableAction>View all assessments</UnavailableAction>
        </section>
        <Activity activity={data.activity} />
      </div>
      <div className="analyst-stack">
        <section className="analyst-card">
          <h2>Needs your attention</h2>
          {data.attention.length ? <ul className="analyst-attention">{data.attention.map(item => <li key={item.id}>
            <p>{item.title}</p><div><small>{item.context}</small><UnavailableAction>{item.action}</UnavailableAction></div>
          </li>)}</ul> : <p>No items need attention.</p>}
        </section>
        <Tools tools={data.tools} />
        <section className="analyst-card">
          <h2>Findings by Severity</h2>
          <small>Consolidated findings</small>
          <ul className="analyst-severity">{severities.map(severity => <li key={severity} data-severity={severity}>
            <span>{severity}</span><span className="analyst-bar" aria-hidden="true"><i style={{ width: `${data.severity[severity] / maximum * 100}%` }} /></span>
            <span>{data.severity[severity]}</span>
          </li>)}</ul>
          <UnavailableAction>View Findings</UnavailableAction>
        </section>
      </div>
    </div>
  </>
}

export default function AnalystDashboard({ state, signingOut, logoutFailed, onSignOut }: {
  state: AnalystDashboardState
  signingOut: boolean
  logoutFailed: boolean
  onSignOut: () => void
}) {
  const [accountOpen, setAccountOpen] = useState(false)
  const accountButton = useRef<HTMLButtonElement>(null)
  const data = state.status === 'ready' ? state.data : undefined
  const populated = Boolean(data?.assessments.length)
  const name = data?.displayName ? `, ${data.displayName}` : ''

  return <div className="analyst-shell">
    <aside className="analyst-sidebar">
      <div className="analyst-logo"><img src={shield} alt="" />UPTIP</div>
      <nav aria-label="Analyst workspace">
        {navigation.map(([label, icon], index) => index === 0
          ? <a href="/analyst/dashboard" aria-current="page" key={label}><img src={icon} alt="" />{label}</a>
          : <button type="button" key={label} disabled title="Unavailable in this release">
            <img src={icon} alt="" />{label}{(index === 1 || index === 2) && <span aria-hidden="true">›</span>}
          </button>)}
      </nav>
    </aside>
    <div className="analyst-workspace">
      <header className="analyst-topbar">
        <span>ANTIC / UPTIP</span>
        <div className="analyst-controls">
          <button type="button" disabled aria-label="Notifications unavailable" title="Notifications unavailable"><img src={bell} alt="" /></button>
          <div className="analyst-account" onKeyDown={event => {
            if (event.key === 'Escape' && accountOpen) {
              setAccountOpen(false)
              accountButton.current?.focus()
            }
          }}>
            <button ref={accountButton} type="button" className="analyst-avatar" aria-label="Account"
              aria-expanded={accountOpen} aria-controls="analyst-account-panel" onClick={() => setAccountOpen(!accountOpen)}>
              {data?.initials || 'SA'}
            </button>
            <div className="analyst-account-panel" id="analyst-account-panel" hidden={!accountOpen}>
              {data?.displayName && <strong>{data.displayName}</strong>}
              <small>Security Analyst</small>
              <UnavailableAction>Account &amp; Security</UnavailableAction>
              <button type="button" onClick={onSignOut} disabled={signingOut}>{signingOut ? 'Signing out…' : 'Sign Out'}</button>
            </div>
          </div>
        </div>
      </header>
      <main className="analyst-content">
        <nav aria-label="Breadcrumb"><span aria-current="page">Dashboard</span></nav>
        <div className="analyst-heading">
          <div><h1>Dashboard</h1><p>{data ? (populated
            ? `Welcome back${name}. Here is where your assessments stand.`
            : `Welcome${name}. Create your first assessment to get started.`)
            : 'Security Analyst workspace'}</p></div>
          <CreateAssessment prominent />
        </div>
        {logoutFailed && <p role="alert">Unable to sign out. Please try again.</p>}
        {state.status === 'loading' && <section className="analyst-card" role="status">Loading dashboard data…</section>}
        {state.status === 'unavailable' && <section className="analyst-card" role="alert">
          <h2>Dashboard data unavailable</h2><p>Assessment activity could not be verified.</p>
        </section>}
        {data && (populated ? <PopulatedDashboard data={data} /> : <EmptyDashboard data={data} />)}
      </main>
    </div>
  </div>
}
