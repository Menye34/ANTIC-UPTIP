# First Login — Set New Password

## Implementation and design

Actual Figma implementation frames inspected: `254:17724` (Default) and
`254:17786` (Passwords Don't Match), Authentication page in ANTIC_UPTIP.
FirstLogin is one React component at `/first-login`, using AuthBrand, the existing
480px authentication card, inputs, visibility icons, alert styles, fonts and
responsive spacing. No Figma design, Login styling or MFA layout was modified.
The default layout is approximately 480 × 579px and the mismatch layout grows by
one existing alert block. Card heights remain content-driven on smaller screens.

Figma displays the five approved rules in one compact sentence, which is retained:
“Use at least 12 characters, with upper and lower case letters, a number and a symbol.”
Both frontend and backend enforce length 12–1024 Unicode code points, uppercase
(category Lu), lowercase (Ll), decimal digit (Nd), and punctuation/symbol (P/S).
Passwords are not trimmed or normalized. Existing transport/body limits apply.

The two fields have independent accessible show/hide controls. Confirmation blur
shows the exact mismatch alert if both values differ; editing removes that alert.
Entered passwords are retained for correction. The action stays disabled until
complexity and equality checks pass, even though the mismatch Figma specimen shows
an active button. This follows the task's explicit client-validation requirement.
Server-side mismatch and policy validation also remain mandatory.

App enters this page only when Login receives `password_change_required` with
`next_step_available=true`. The page then validates the actual server challenge
before enabling inputs. Opening `/first-login` directly grants no authority; an
invalid or expired challenge returns to Login. A network/service failure does not
fabricate authorization. No password, raw challenge or CSRF token is stored in a
URL or browser storage. Sensitive form values are cleared on completion/unmount.

## API and security

| Endpoint | Contract |
| --- | --- |
| Existing POST `/api/v1/auth/login` | Correct temporary password and active account issue a password-change challenge before MFA. |
| GET `/api/v1/auth/password/challenge` | Verify pending cookie, password fingerprint, account state, environment and expiry; return purpose-bound CSRF token. |
| POST `/api/v1/auth/password/change` | JSON `new_password` and `confirmation`; trusted Origin and X-CSRF-Token required. |

The new password-change cookie is `__Host-uptip_password_change` for HTTPS or
`uptip_dev_password_change` under the existing HTTP development configuration.
It is HttpOnly, SameSite=Strict, Path=/ and Secure according to the existing
validated environment settings. Its lifetime is five minutes. The token contains
256 bits of cryptographic randomness; only its SHA-256 digest is stored. The
challenge binds user ID, password-hash fingerprint and environment. The CSRF HMAC
uses a password-change-specific domain, distinct from MFA and normal sessions.
No new configuration secret or dependency is needed.

The challenge can only be created after real password verification and account
eligibility checks. It cannot access the protected session endpoint, authorize MFA
verification, or become an authenticated session. The replacement endpoint reuses
existing shared IP and per-subject rate limits and takes user → challenge row locks.
A replay, changed password credential, disabled account, cleared requirement or
expired challenge is rejected. Concurrent submissions can succeed only once.

Replacement enforces matching confirmation and all complexity checks, rejects
reuse of the current temporary password with Argon2id verification, hashes the new
password using the existing hasher and clears password_change_required. Within the
same transaction it revokes this user's existing AuthSessions and consumes all of
this user's password-change and MFA challenges, then records password_changed.
MFA credentials, replay counters, lockout state and policy are not reset.

Success returns `password_changed`, not `authenticated`. No normal session is
created. Cookies for the completed flow are cleared, the page clears sensitive
state and returns to empty Login. The user must authenticate using the new
password. Existing backend account and MFA rules then choose the next step; no
MFA enrollment/verification or role workflow is bypassed. Production MFA policy
and MFA Setup UI remain separate dependencies, unchanged by this feature.

Other response states reuse AuthResponse: password_mismatch (422),
password_rejected (422), challenge_expired (401), forbidden (403), rate_limited
(429) and existing generic service errors. Passwords never appear in responses or
audit records. Existing validation-error redaction and SQL parameter hiding remain.

## Migration

Alembic revision `0003`, after `0002`, creates password_change_challenges with a
hashed-token primary key, user FK, password fingerprint, expiry, consumed flag and
environment. User.password_change_required is reused. There are no account,
credential, role or policy seeds and no existing account flags are changed by the
migration. Periodically purge expired/consumed challenges through trusted database
maintenance, alongside the existing challenge/session retention process.

## Exact localhost setup and test commands

Run from the repository root (the directory containing package.json and backend/).
Retain the existing ignored local .env and PostgreSQL configuration from
[Authentication setup](authentication.md). Do not commit populated .env files.

```bash
git switch feat/authentication-module
git pull --ff-only origin feat/authentication-module
npm ci
.venv/bin/pip install -r backend/requirements-dev.txt
.venv/bin/alembic -c backend/alembic.ini upgrade head
```

Create a new, disposable development account with the default temporary-password
state. The existing provisioning command requires development environment,
prompts for its password, and does not echo or commit it. Use an actual approved
UPTIP role name; no production role catalogue is invented here.

```bash
PYTHONPATH=backend .venv/bin/python -m app.provision --username '<new-development-test-user>' --role '<approved-role-name>'
```

Do not pass --password-already-replaced: the account must require First Login.
Do not disable MFA to force completion. Start the backend in one terminal:

```bash
.venv/bin/uvicorn app.main:create_app --factory --app-dir backend --host 127.0.0.1 --port 8000 --no-proxy-headers
```

Start the frontend in another terminal:

```bash
npm run dev
```

Open exactly http://localhost:5173 for the existing development PUBLIC_ORIGIN.
Sign in with the test user's temporary password. Confirm the First Login page
appears, independently test both eye controls, then enter a compliant password and
a different confirmation. Blur confirmation to inspect the red Figma alert.
Correct confirmation: the button enables. Submit and confirm return to Login with
empty fields. The old password must fail; the new password must be accepted and
then follow the account's existing MFA requirement. An MFA-required, unenrolled
account will stop at the existing enrollment-required response; this is expected.
Opening /first-login without a challenge must return to Login. A five-minute-old
challenge must not replace a password, even if the form remains open.

Automated checks:

```bash
npm test
npm run lint
npm run build
export UPTIP_TEST_DATABASE_URL='postgresql+psycopg://uptip:<test-database-password>@127.0.0.1:5432/uptip_test'
.venv/bin/python -m pytest backend/tests -q
```

Use a disposable database whose name contains test; the backend suite migrates and
truncates it. Credentials in test fixtures are not application seeds. The suite
covers challenge issuance/expiry/replay, complexity, mismatch, temporary-password
reuse, CSRF/origin, concurrent changes, revocation, audit safety and fresh Login.
It also runs existing Login and MFA tests and compares migrations with models.

## Verification performed and limits

Frontend: 61 tests passed, lint passed, production build/type checks passed.
Backend: 46 tests passed against PostgreSQL, including migration downgrade/upgrade
and schema comparison. One upstream Starlette/httpx test-client deprecation warning
remains. No tests were marked passing without execution.

A real localhost smoke check started npm run dev and Uvicorn with a temporary,
isolated PostgreSQL database and generated, uncommitted credentials. Through
Vite's API proxy it verified SPA/module/logo serving, missing-challenge denial,
correct temporary-password login, mismatch rejection, successful replacement,
absence of an authenticated session, rejection of the old password and acceptance
of the new password with the MFA enrollment gate still enforced. The temporary
database was deleted afterward; no application database was modified.

The Figma references and DOM/CSS states were inspected/tested. A rendered browser
comparison remains for Kali because the hosted Chromium process cannot create its
required Unix socket. No pixel-perfect screenshot comparison is claimed.

## File inventory

| Change | File |
| --- | --- |
| Modified | `README.md` |
| Modified | `backend/app/config.py` |
| Modified | `backend/app/main.py` |
| Modified | `backend/app/models.py` |
| Modified | `backend/app/routes.py` |
| Modified | `backend/app/schemas.py` |
| Modified | `backend/app/service.py` |
| Modified | `backend/tests/test_auth.py` |
| Modified | `backend/tests/test_mfa.py` |
| Modified | `docs/authentication.md` |
| Modified | `docs/mfa-verification.md` |
| Modified | `src/App.tsx` |
| Modified | `src/components/Login.tsx` |
| Modified | `src/services/auth.ts` |
| Created | `backend/app/password_routes.py` |
| Created | `backend/app/password_service.py` |
| Created | `backend/migrations/versions/0003_password_change.py` |
| Created | `backend/tests/test_password_change.py` |
| Created | `docs/first-login.md` |
| Created | `src/components/FirstLogin.css` |
| Created | `src/components/FirstLogin.test.tsx` |
| Created | `src/components/FirstLogin.tsx` |
| Created | `src/services/password.ts` |
