import uptipLogo from '../assets/uptip-logo.svg'

export default function AuthBrand() {
  return <div className="login-brand">
    <p className="login-institution">ANTIC</p>
    <img className="login-logo" src={uptipLogo} width="108" height="25" alt="UPTIP" />
    <p className="login-platform-name">Unified Penetration Testing Intelligent Platform</p>
  </div>
}
