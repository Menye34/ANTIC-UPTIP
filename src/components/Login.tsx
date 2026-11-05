import { useState } from 'react'
import uptipLogo from '../assets/uptip-logo.svg'
import passwordVisibilityIcon from '../assets/password-visibility.svg'
import './Login.css'

/** Authentication → Login — default, Figma node 44:2587. */
export default function Login() {
  const [passwordVisible, setPasswordVisible] = useState(false)

  return (
    <main className="login-page">
      <form className="login-card" aria-labelledby="login-heading"
        onSubmit={(event) => event.preventDefault()}>
        <div className="login-brand">
          <p className="login-institution">ANTIC</p>
          <img className="login-logo" src={uptipLogo} width="108" height="25" alt="UPTIP" />
          <p className="login-platform-name">Unified Penetration Testing Intelligent Platform</p>
        </div>
        <header className="login-heading">
          <h1 id="login-heading">Sign in to UPTIP</h1>
          <p>Secure access for authorized users.</p>
        </header>
        <div className="login-fields">
          <div className="login-field">
            <label htmlFor="username">Username</label>
            <input id="username" name="username" type="text" autoComplete="username"
              autoCapitalize="none" spellCheck={false} placeholder="Enter your username" defaultValue="" />
          </div>
          <div className="login-field">
            <label htmlFor="password">Password</label>
            <div className="login-password">
              <input id="password" name="password" type={passwordVisible ? 'text' : 'password'}
                autoComplete="current-password" placeholder="Enter your password" defaultValue="" />
              <button className="login-password-toggle" type="button"
                aria-label={passwordVisible ? 'Hide password' : 'Show password'}
                aria-pressed={passwordVisible} aria-controls="password"
                onClick={() => setPasswordVisible((visible) => !visible)}>
                <img src={passwordVisibilityIcon} width="16" height="16" alt="" />
              </button>
            </div>
          </div>
        </div>
        <button className="login-submit" type="submit" disabled>Sign In</button>
        <p className="login-help">Need help signing in? Contact your administrator.</p>
      </form>
    </main>
  )
}
