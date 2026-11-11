import { useRef, useState } from 'react'
import bell from '../assets/analyst/NotificationBell.svg'
import shield from '../assets/analyst/ApprovedLinkedNodesShield.svg'
import dashboard from '../assets/analyst/LayoutDashboard.svg'
import scope from '../assets/analyst/ShieldCheck.svg'
import document from '../assets/analyst/FileText.svg'
import './AnalystDashboard.css'
import type { ReactNode } from 'react'

const navigation = [
  ['Dashboard', dashboard], ['Assessments', scope], ['Scope & Targets', scope],
  ['Testing', document], ['Findings', document], ['Report', document], ['Audit Log', document],
]

export default function AnalystShell({ children, displayName, initials, signingOut, onSignOut, sidebar = true, createActive = false, scopeOverview, targetsActive = false }: {
  children: ReactNode
  displayName?: string
  initials?: string
  signingOut: boolean
  onSignOut: () => void
  sidebar?: boolean
  createActive?: boolean
  scopeOverview?: string
  targetsActive?: boolean
}) {
  const [accountOpen, setAccountOpen] = useState(false)
  const accountButton = useRef<HTMLButtonElement>(null)
  return <div className={sidebar ? "analyst-shell" : "analyst-shell assessment-shell-wide"}>
    {sidebar && <aside className="analyst-sidebar">
      <div className="analyst-logo"><img src={shield} alt="" />UPTIP</div>
      <nav aria-label="Analyst workspace">
        {navigation.map(([label, icon], index) => index === 0
          ? <a href="/analyst/dashboard" aria-current={createActive || scopeOverview ? undefined : "page"} key={label}><img src={icon} alt="" />{label}</a>
          : scopeOverview && index === 1 ? <a href={scopeOverview} key={label}><img src={icon} alt="" />Assessment</a>
          : scopeOverview && index === 2 ? <div className="analyst-assessment-nav" key={label}>
            <details open><summary><img src={icon} alt="" />Setup</summary>
              <a href={scopeOverview + '/scope'} aria-current={targetsActive ? undefined : "page"}>Authorized Scope</a>
              <a href={scopeOverview + '/targets'} aria-current={targetsActive ? "page" : undefined}>Assessment Targets</a>
            </details>
          </div>
          : index === 1 ? <div className="analyst-assessment-nav" key={label}>
            <details open={createActive || undefined}><summary><img src={icon} alt="" />{label}</summary>
              <a href="/analyst/assessments/new" aria-current={createActive ? 'page' : undefined}>Create Assessment</a>
            </details>
          </div> : <button type="button" key={label} disabled title="Unavailable in this release">
            <img src={icon} alt="" />{scopeOverview && label === 'Report' ? 'Reports' : label}{index === 2 && <span aria-hidden="true">›</span>}
          </button>)}
      </nav>
    </aside>}
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
              {initials || 'SA'}
            </button>
            <div className="analyst-account-panel" id="analyst-account-panel" hidden={!accountOpen}>
              {displayName && <strong>{displayName}</strong>}
              <small>Security Analyst</small>
              <button type="button" className="analyst-link" disabled>Account &amp; Security</button>
              <button type="button" onClick={onSignOut} disabled={signingOut}>{signingOut ? 'Signing out…' : 'Sign Out'}</button>
            </div>
          </div>
        </div>
      </header>
      {children}
    </div>
  </div>
}
