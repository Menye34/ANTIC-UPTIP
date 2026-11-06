# Authentication foundation

## Scope and repository inspection

The original repository contains a root Vite/React/TypeScript/CSS application,
`src/components/Login.tsx`, Figma SVG assets and self-hosted Inter fonts. It has no
backend, database, migrations, role definitions or authentication requirements
beyond the supplied task. `feat/login-default` and draft PR #1 are preserved.
`feat/authentication-module` starts from that branch's remote commit
`21e1f0a97ad5912c9dbb4fb852fa1a384c7c8f22`.

The backend uses FastAPI, synchronous SQLAlchemy sessions, psycopg, PostgreSQL,
Alembic and argon2-cffi (Argon2id). No accounts or application roles are seeded.
Roles are records with approved names supplied by the operator, not an invented
application role catalogue. Test-fixture role names exist only in tests.

## Kali Linux development setup

Use Python 3.12+, Node 22.12+ (or the version required by installed Vite), npm and
PostgreSQL 16+. Run these commands from the repository root unless stated.

```bash
sudo apt update
sudo apt install python3 python3-venv postgresql postgresql-client
sudo systemctl enable --now postgresql
python3 -m venv .venv
.venv/bin/pip install -r backend/requirements-dev.txt
npm ci
sudo -u postgres createuser --pwprompt uptip
sudo -u postgres createdb --owner=uptip uptip
cp .env.example .env
.venv/bin/python -c 'import secrets; print(secrets.token_urlsafe(48))'
```

Edit local `.env`: replace the database-password placeholder (URL-encode reserved
characters) and paste the generated random value into `UPTIP_RATE_KEY`. The rate
key pseudonymizes IP and username bucket keys; it is not a shared login password.
Never commit `.env`, passwords, production database dumps or authentication tokens.

```bash
.venv/bin/alembic -c backend/alembic.ini upgrade head
.venv/bin/uvicorn app.main:create_app --factory --app-dir backend --host 127.0.0.1 --port 8000 --no-proxy-headers
```

In another terminal:

```bash
npm run dev
```

Open exactly `http://localhost:5173`. Vite forwards `/api` to loopback port 8000.
The browser Origin must match `UPTIP_PUBLIC_ORIGIN` exactly. No cross-origin CORS
access is enabled. HTTP development uses a separate `uptip_dev_session` cookie
with HttpOnly and SameSite=Strict, but Secure=false **only in development**.
Production defaults to Secure=true and rejects an insecure origin/cookie setting.
For HTTPS development use an HTTPS frontend proxy and Secure=true; the backend
can remain on loopback behind that trusted proxy.

## Provision a development account

No default administrator or known password exists. The command refuses to run
outside `UPTIP_ENVIRONMENT=development` and prompts without echoing passwords.
Supply a role name from the approved UPTIP catalogue (not provided in this repo):

```bash
PYTHONPATH=backend .venv/bin/python -m app.provision --username analyst-01 --role '<approved-role-name>'
```

Default provisioning requires password replacement and MFA, so login returns a
pending state with no session. To exercise the complete session path **only with
an explicitly permitted development account policy**:

```bash
PYTHONPATH=backend .venv/bin/python -m app.provision --username '<development-username>' --role '<approved-role-name>' --password-already-replaced --mfa-not-required
```

These flags do not disable gates globally and cannot satisfy MFA for an enrolled
account. Password input must be at least 12 characters; no password is accepted
through command-line arguments. Duplicate usernames fail rather than overwriting
accounts. Provisioning does not implement production account administration.

## API and state contract

All authentication responses have `state`, `message`, `next_step_available`
(default false), and `csrf_token` (null except a completed login). Login accepts
only JSON `{ "username": "...", "password": "..." }`. Username is case-sensitive,
1–128 ASCII letters/digits/`._@-`, starts alphanumeric; passwords are 1–1024
characters and are never trimmed. Additional JSON keys are rejected. Request
bodies over 8192 bytes are rejected before JSON parsing, including chunked bodies.

| Endpoint | Behavior |
| --- | --- |
| `POST /api/v1/auth/login` | Validate credentials and gates; exact trusted Origin required. |
| `GET /api/v1/auth/session` | Protected session check. No token or account details returned. |
| `POST /api/v1/auth/logout` | Revoke session; trusted Origin and `X-CSRF-Token` required. |

| State | HTTP | Implemented behavior |
| --- | --- | --- |
| `invalid_credentials` | 401 | Unknown usernames and incorrect passwords (including disabled/locked accounts) share the approved generic message. |
| `account_unavailable` | 403 | Disclosed for a disabled/locked account only after verifying its correct password; no session issued. |
| `password_change_required` | 200 | Valid temporary credentials issue a restricted password-change challenge; First Login must complete, then fresh Login is required. No session is granted. |
| `mfa_enrollment_required` | 200 | Policy requires MFA and enrollment is absent; no session. |
| `mfa_verification_required` | 200 | Enrolled or required MFA; no session, including when a historic verification timestamp exists. |
| `authenticated` | 200 | Only active users with no password-change requirement and no required/enrolled MFA receive a session. |
| `rate_limited` | 429 | Wait for the fixed-window expiry; Retry-After supplied conservatively. |
| `invalid_request` | 413/422 | Generic response without submitted values. |
| `forbidden` | 403 | Origin/CSRF check failed. |
| `unauthenticated` | 401/200 | Missing/invalid session; or successful logout. |
| `session_expired` | 401 | Recognized expired session; expired browser cookie removed. |
| `unavailable` | 503 | Database error, no internal details exposed. |

First Login password replacement now uses a purpose-bound, expiring challenge;
see [First Login](first-login.md). MFA Verification is available through the
explicit development harness described in [MFA Verification](mfa-verification.md).
MFA enrollment UI and the production MFA policy adapter remain unimplemented.
Neither pending challenge is an authenticated session or grants protected access.

## Security mechanisms and operational limits

- Argon2id password hashes; missing users use a dummy Argon2id verification.
  Hashes are upgraded after valid verification when parameters change.
- Independent cryptographically random 256-bit session/CSRF tokens; only SHA-256
  digests stored server-side. Tokens are never stored in localStorage. Frontend
  retains the CSRF token only in memory; refresh requires signing in again for a
  subsequent mutation until a dedicated CSRF refresh interface is implemented.
- Production cookie: `__Host-uptip_session`, Secure, HttpOnly, SameSite=Strict,
  Path=/, no Domain; default 30-minute absolute expiry. New login revokes the
  previous cookie's session. Other devices retain their sessions until expiry or
  policy change. No remember-me/refresh token is implemented.
- Every protected request checks active status and password/MFA policy again.
  All future state-changing cookie-authenticated routes must reuse Origin and
  constant-time synchronizer-token checks; currently logout is the only one.
  Login has strict Origin validation to prevent login CSRF.
- Database-backed atomic fixed-window buckets shared across processes: default
  30 attempts per source IP and 10 per username in 900 seconds. Valid and failed
  login attempts both count. Windows may allow a burst across a boundary; no
  permanent account lockout or distributed network-edge DDoS service is implied.
  Username throttling can temporarily affect a targeted account; tune limits to
  policy. Invalid schema requests do not reach password verification.
- IP and username rate keys use HMAC. Auth audit records contain reason, internal
  user ID when known, pseudonymous client key, timestamp; never passwords, hashes,
  request bodies, cookies or CSRF tokens. Audit records have no public endpoint;
  restrict database access and backups. SQLAlchemy hides SQL parameter values.
- Behind a reverse proxy, configure exactly trusted proxy peers before enabling
  forwarded headers. Never trust arbitrary X-Forwarded-For. Default startup above
  ignores forwarded headers; otherwise all users could share the proxy IP bucket.
- Production requires TLS termination, same-origin frontend/API routing, private
  PostgreSQL, a least-privilege DB role (separate migration owner), database TLS
  configuration and restricted logs. Rate limits complement an edge connection
  and request timeout/size policy; they are not a DDoS defense.
- Schedule retention for audit records under organizational policy. Periodically
  delete expired sessions and stale rate buckets in a trusted maintenance job:
  `DELETE FROM auth_sessions WHERE expires_at < now();`
  and delete `login_buckets` whose window is older than the previous configured
  window. Do not expose cleanup as a public API. This foundation has no scheduler.

## Frontend integration and verification

App.tsx still renders the separate Login component. Original Default markup,
branding, fonts, dimensions and disabled style are retained. Controlled empty
fields enable submission only when both contain values. The real API request uses
same-origin credentials, a 15-second timeout and an immediate in-flight guard.
The button displays `Signing in...`; repeated submits are blocked. Password input
is retained for invalid credentials and network retry, and cleared for account
unavailability or other completed responses. Errors and pending states use the Figma alert above the fields; the card expands
only when a response message is present. No dashboard
navigation occurs, even on completed authentication.

To verify communication, inspect the browser Network tab for the login POST and
its structured state; never share credential-bearing request captures. Missing
backend produces the retryable network/service error. Pending accounts must not
have a session cookie, and GET `/api/v1/auth/session` must return 401. Completed
login sets an HttpOnly cookie; the protected GET returns 200. Logout requires the
CSRF token from the completed login response and the original Origin.

### Automated checks

```bash
npm test
npm run lint
npm run build
sudo -u postgres createdb --owner=uptip uptip_test
export UPTIP_TEST_DATABASE_URL='postgresql+psycopg://uptip:<test-database-password>@127.0.0.1:5432/uptip_test'
.venv/bin/python -m pytest backend/tests -q
```

Use a **disposable** test database: tests migrate and truncate its tables. Its name
must contain `test`; never point this at production. Without the test URL,
integration tests explicitly skip (not pass). Tests run Alembic downgrade/upgrade,
compare the schema with SQLAlchemy models, and exercise PostgreSQL atomic limits,
valid/invalid credentials, account states, sessions, expiry, rotation, CSRF,
MFA/password gates, audit safety and bounded request bodies.

Frontend tests use jsdom with mocked transport only; production code never mocks
responses. They verify Default, empty-field blocking, actual fetch contract,
loading, duplicate prevention, errors/retry and no unauthorized navigation.
They do not establish a pixel-perfect browser/Figma comparison. Browser visual
verification remains outstanding in this workspace because Chromium cannot open
the required process socket; no screenshot match is claimed.

## Approved Login scenarios (Figma inspection)

These are the actual 1440 × 900 implementation frames, not the 1440 × 936 review wrappers.
All cards remain 480px wide, with 32px padding, 24px section gaps and existing Inter fonts.

| Scenario | Node | Card height | Behavior |
| --- | --- | --- | --- |
| Login — Default | 44:2587 | 497px | Empty fields, disabled gray Sign In. |
| Login — Filled/Ready | 205:323 | 497px | Both values present; blue #2563EB button with white text. |
| Login — Signing In | 205:356 | 497px | Disabled slate fields/button; Signing in...; no duplicate submission. |
| Login — Invalid Credentials | 205:387 | 597px | Red error alert above fields; both values retained, Sign In ready. |
| Login — Account Unavailable | 205:427 | 597px | Blue info alert; username retained, password cleared, Sign In disabled. |
| Session expired | 254:17720 | 575px | Blue info alert; both fields empty. |
| Login — Caps Lock on | 254:17857 | 531px | Caps Lock is on, amber #92400E, 12/18px below password, no warning icon. |

Focus uses a 2px blue boundary and 3px #BFDBFE ring. Alert icons are exact 20px SVG
exports from Figma, with 16px padding, 12px icon/message gap, 6px radius, 14/22px
body text. Red: #FEF2F2 / #FECACA / #991B1B. Info: #EFF6FF / #BFDBFE / #1D4ED8.
Alert heights use inside borders so text width matches Figma.

Password visibility is an accessible 32px toggle containing a 16px glyph. It
changes the actual input type and preserves its value. Figma's Visible master
203:1248 repeats the same eye-off asset as Hidden. To fulfill the explicit
open-eye interaction requirement, the visible glyph uses the corresponding
Lucide eye SVG with the same 16px slate (#475569) treatment and 1px rendered
stroke. The original Figma eye-off remains unchanged. Lucide's license is in
src/assets/lucide-LICENSE.txt. No Figma nodes were edited.

### Session-expiry detection

Login checks the real session endpoint on mount, every 30 seconds and on window
focus/visibility restoration. A 401 is only treated as session expiry if the
server recognizes an expired session or this tab previously observed a real
successful login/session. A non-sensitive boolean in sessionStorage preserves
that UI hint across reloads; it grants no authority and stores no secret. A first
visit with no previous authenticated state remains Default. Network/server
failures do not imply expiry. An expired-cookie response removes the stale cookie
to prevent repeated notices from clearing credentials on later checks. Future
intentional logout UI must call clearKnownSession after successful logout.

### Manual Kali test checklist

Pull feat/authentication-module and use the startup commands above. No new
migration or configuration variable is required for the Login scenario changes.

1. Open http://localhost:5173 at 1440 × 900. Confirm Default has empty fields and
   a gray disabled button. Fill just one field: it remains disabled. Fill both:
   the button immediately turns blue. Compare with 205:323.
2. Click the password toggle, then activate it using keyboard Enter/Space.
   Confirm visible text/open eye, hidden text/crossed eye and unchanged value.
3. Submit a real request. With browser network throttling, confirm disabled fields,
   Signing in... and exactly one login POST while pending (205:356).
4. Enter an unknown username or incorrect password: the exact red Figma message
   appears above fields; entered values remain and the button returns to blue.
5. For a disposable development account, set status to disabled in the development
   database and submit its **correct** password. Expect the blue Account
   Unavailable message, retained username and cleared password. A wrong password
   for the same disabled account must still show the generic invalid message.
   Restore the account status afterward; never perform this on production users.
6. Switch Caps Lock on while typing, then off. Confirm the amber text appears
   below password and disappears, without altering the button's readiness.
7. Complete login using a development account explicitly permitted to use
   password-only authentication. For a quick expiry test set
   UPTIP_SESSION_SECONDS=60, restart the backend, sign in, wait past 60 seconds,
   then focus the window or wait for the next 30-second check. Expect Session
   Expired with empty fields. An ordinary first visit must never show it.
8. Stop the backend and submit: receive a retryable non-sensitive service error,
   retain credentials and restore the button. Resume backend service and retry.

MFA/password-change accounts still stop at their safe pending response; their UI
and dashboard navigation remain out of scope. Local automated tests check the
actual CSS color rules in jsdom and the DOM/API contracts, not a pixel screenshot.
