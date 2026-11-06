# MFA Verification

## Scope and policy dependency

One React page implements five actual Authentication Figma frames:
205:465 (Default), 254:17586 (Invalid Code), 254:17590 (Code Expired),
254:17654 (Too Many Attempts), and 254:17658 (Verifying). The shared white card
is 480 × 431px, or 480 × 531px with the approved two-line alert. It uses the
existing 32px padding, 24px gaps, Inter fonts, branding and responsive card rules.
Only the warning icon is a new Figma SVG export; the logo and error/info icons
reuse existing exact exports. No Figma content was changed.

The repository has **no approved production MFA decision source or failed-attempt
threshold**. This implementation does not invent either. Production Login keeps
the existing MFA gating behavior; it cannot bypass required MFA. First Login
password replacement is now implemented separately (see docs/first-login.md). A production MFA policy adapter must be approved and implemented
before production can issue verification challenges. No policy-management UI is
added. Existing account flags are preserved; they are not claimed to be a newly
approved policy.

The isolated development harness is restricted to one explicitly configured
username, `UPTIP_ENVIRONMENT=development`, an explicit operator-chosen test attempt
limit and an encryption key. Production startup rejects a configured development
username; production also rejects development MFA challenges and their session
proofs. Copying the development configuration into production cannot activate it.
Use separate development and production databases and keys.

## Flow and API

Login validates the password, active status and password-replacement gate first.
For the configured, MFA-enrolled development account only, it issues a five-minute
pending MFA challenge and returns the existing `mfa_verification_required` state
with `next_step_available=true`. This causes App to render MfaVerification at
`/mfa`. Other users and all production accounts retain the existing Login outcome.
An account requiring enrollment still returns `mfa_enrollment_required`; no Setup
screen is implemented. A mandatory password change always takes precedence.

| Endpoint | Purpose |
| --- | --- |
| `GET /api/v1/auth/mfa/challenge` | Resume/status-check the server-bound challenge and obtain its purpose-bound CSRF token; report persisted lockout. |
| `POST /api/v1/auth/mfa/verify` | JSON `{ "code": "<six digits>" }`, trusted Origin and `X-CSRF-Token`; verify real TOTP and promote exactly once. |
| `POST /api/v1/auth/mfa/cancel` | Trusted Origin and challenge CSRF; consume pending challenge, remove its cookie, preserve unrelated authenticated sessions. Idempotent if no pending cookie remains. |

Outcomes extend the existing AuthResponse schema: `invalid_code`, `code_expired`
(reserved, see below), `too_many_attempts`, `challenge_expired`, `mfa_cancelled`.
Successful verification reuses `authenticated` and returns the normal session
CSRF token. No duplicate success contract is introduced. No codes, authenticator
secrets or raw pending tokens appear in ordinary JSON responses.

The challenge uses a separate random 256-bit HttpOnly, SameSite=Strict cookie
(`__Host-uptip_mfa` under HTTPS, `uptip_dev_mfa` for HTTP loopback development).
Only its SHA-256 digest is stored. Its derived CSRF token is purpose-bound and
cannot authorize a normal cookie-authenticated mutation. The challenge is bound
to the account, credential ID, password fingerprint, expiry and environment.
It is not an AuthSession, so pending authentication cannot access the protected
session endpoint. Account status and password-change requirements are rechecked.
A new password-authenticated challenge consumes older challenges for that account.

## TOTP, secret storage and replay protection

PyOTP performs standard six-digit TOTP verification at 30-second intervals.
The tolerance is exactly the previous, current and next time step (±30 seconds).
Keep server and authenticator clocks synchronized. Leading zeroes remain strings.
TOTP secrets are encrypted with authenticated Fernet encryption using an external
`UPTIP_MFA_ENCRYPTION_KEY`. No secrets are seeded or committed. Restrict database,
backup and environment access. Key rotation requires a controlled re-encryption
of stored credentials before changing the active key; losing the key requires
re-enrollment through a future approved recovery workflow.

The credential records a monotonic last-accepted TOTP step. Transactions lock
account → credential → challenge in a consistent order. Concurrent requests cannot
accept the same step or consume the challenge twice. A historic account-level MFA
timestamp alone cannot authorize any request. AuthSession contains the verified
credential reference, and protected requests recheck the account and session proof.
An MFA-proof session from the development harness is not accepted in production.

An arbitrary six-digit rejected TOTP cannot reliably reveal whether it was mistyped
or generated for an old interval. Therefore **the backend returns generic
`invalid_code`, not `code_expired`, for codes outside the accepted window**.
The exact Code Expired Figma state is implemented and contract-tested for a future
reliable backend outcome, but is not fabricated by a frontend timer or debug flag.

## Attempt restrictions

No permanent production threshold is selected. To enable the development harness,
the operator must supply `UPTIP_DEV_MFA_MAX_ATTEMPTS` (1–100 is the accepted test
configuration range). This is a local test setting, not an approved UPTIP policy.
The failed-attempt counter and lockout live on the account credential, not in
React, cookies or a particular challenge. Reaching the supplied test limit locks
verification for exactly 15 minutes. Blocked requests do not increment counters
or move the existing lockout deadline. Cancellation, refresh and fresh Login do
not reset it. A correct password never bypasses an active MFA restriction.

After lockout expiry, start a fresh password login because challenges expire after
five minutes. The next verification resets the expired restriction under a lock.
The UI does not use a timer to unlock verification or judge TOTP expiry. Back to
Sign In remains available. Normal Login request throttling is also unchanged.

Audit records log issuance via the existing MFA-required event, invalid attempts,
lockout, verification success and cancellation without codes or secrets. Database
errors remain generic and SQL parameters are hidden. Retain audit records under
organizational policy; periodically purge consumed/expired mfa_challenges through
a trusted maintenance process, alongside the existing expired-session cleanup.

## React state and cancellation

MfaVerification owns only transient code, notice, readiness, verifying and locked
state. It reads the authoritative challenge on mount, including after `/mfa`
reload. Verify enables only for exactly six ASCII digits and a usable challenge.
Input is disabled and preserved while Verifying; duplicate submits are blocked.
Invalid Code keeps the input; editing removes its alert. Code Expired clears input
and its alert clears on editing. Lockout clears/disables input and Verify.
Network failures preserve the code and are not presented as invalid codes.

Back aborts the local in-flight request, calls backend cancellation, clears the
code and navigates to a fresh Login component only after cancellation succeeds.
If the service is unreachable, cancellation reports an error rather than claiming
that the challenge was invalidated. Request generations suppress obsolete replies.
Concurrent cancellation and valid verification are serialized: a cancellation
cannot retroactively undo authentication that already committed after a real
valid TOTP, and never deletes unrelated AuthSessions.

No verification code or pending token is stored in browser storage or in a URL.
The shared Login session-observation boolean remains non-sensitive. Successful
MFA establishes a real session and returns to the existing Authentication Complete
notice. Dashboard navigation, role dashboards, MFA Setup and QR enrollment UI
remain outside this task. First Login is documented in docs/first-login.md.

## Kali Linux: pull, configure, run

From the existing repository directory, preserve any local uncommitted work first:

```bash
git switch feat/authentication-module
git pull --ff-only origin feat/authentication-module
npm ci
.venv/bin/pip install -r backend/requirements-dev.txt
```

If this is a new checkout, follow docs/authentication.md first for Python/Node,
PostgreSQL, `.venv`, `.env` and the existing application database setup.
Generate a separate encryption key in a private terminal:

```bash
.venv/bin/python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

Edit the ignored local `.env` (never commit it):

```dotenv
UPTIP_ENVIRONMENT=development
UPTIP_DEV_MFA_USERNAME=<dedicated-development-username>
UPTIP_DEV_MFA_MAX_ATTEMPTS=<operator-chosen-test-limit>
UPTIP_MFA_ENCRYPTION_KEY=<generated-key>
```

Retain the existing DATABASE_URL, RATE_KEY, PUBLIC_ORIGIN and cookie settings.
Use exactly `http://localhost:5173` for the existing HTTP development configuration.
Production HTTPS/Secure cookie requirements have not been relaxed.

```bash
.venv/bin/alembic -c backend/alembic.ini upgrade head
PYTHONPATH=backend .venv/bin/python -m app.provision --username '<dedicated-development-username>' --role '<approved-role-name>' --password-already-replaced
PYTHONPATH=backend .venv/bin/python -m app.mfa_provision
```

Use a new dedicated account. No default role or password is assumed. Provisioning
prompts for the password without echo. MFA provisioning refuses production,
ineligible accounts and existing credentials. It displays a **private enrollment
URI containing the new secret** solely in your terminal; manually add its secret
to a standard authenticator as TOTP, six digits, 30 seconds. Do not share terminal
captures or paste it into hosted QR generators. Enter the authenticator code at
the hidden prompt to prove enrollment. Nothing is saved if verification fails.
The enrollment time step is marked used: wait for the next code before signing in.

Start backend and frontend in separate terminals:

```bash
.venv/bin/uvicorn app.main:create_app --factory --app-dir backend --host 127.0.0.1 --port 8000 --no-proxy-headers
```

```bash
npm run dev
```

Open `http://localhost:5173`, sign in with the dedicated account password, then use
the actual authenticator code. Invalid codes exercise Invalid Code. Repeated
incorrect codes exercise the chosen development limit and 15-minute lockout.
Back to Sign In must cancel; refresh `/mfa` must recheck the backend challenge.
A user with password replacement required must not proceed to verification.
Other users' Login behavior must remain unchanged. Code Expired is contract-tested
only because reliable expiry discrimination is unavailable for arbitrary TOTP.

## Tests and migration

Migration `0002` creates mfa_credentials and mfa_challenges and adds the nullable
MFA credential reference to auth_sessions. No production account flags, roles,
credentials, secrets or policies are seeded or changed.

```bash
npm test
npm run lint
npm run build
export UPTIP_TEST_DATABASE_URL='postgresql+psycopg://uptip:<test-database-password>@127.0.0.1:5432/uptip_test'
.venv/bin/python -m pytest backend/tests -q
```

The PostgreSQL test database must be disposable (its name must contain `test`).
The suite migrates/truncates it. Tests use generated secrets and real TOTP, never
an accepted hardcoded code. No test account is created in the application DB.
The test-fixture limit is not a policy selection. Migration schema comparison and
all existing Login/security regression tests are included.

Frontend tests use jsdom with mocked transport, checking actual CSS rules and
state behavior. This is not a browser pixel comparison; rendered visual validation
remains for Kali if Chromium cannot launch in the hosted workspace.

The Code Expired Figma specimen shows a blue Verify button with an empty field.
The implementation follows the explicit task requirement: Verify stays disabled
until six digits have been entered, including after Code Expired.

## Files in this change

| Change | File |
| --- | --- |
| Modified | `.env.example` |
| Modified | `README.md` |
| Modified | `backend/app/config.py` |
| Modified | `backend/app/main.py` |
| Modified | `backend/app/models.py` |
| Modified | `backend/app/routes.py` |
| Modified | `backend/app/schemas.py` |
| Modified | `backend/app/security.py` |
| Modified | `backend/app/service.py` |
| Modified | `backend/requirements.txt` |
| Modified | `src/App.tsx` |
| Modified | `src/components/Login.tsx` |
| Modified | `src/services/auth.ts` |
| Created | `backend/app/mfa_provision.py` |
| Created | `backend/app/mfa_routes.py` |
| Created | `backend/app/mfa_service.py` |
| Created | `backend/migrations/versions/0002_mfa_verification.py` |
| Created | `backend/tests/test_mfa.py` |
| Created | `docs/mfa-verification.md` |
| Created | `src/assets/mfa-warning.svg` |
| Created | `src/components/AuthBrand.tsx` |
| Created | `src/components/MfaVerification.css` |
| Created | `src/components/MfaVerification.test.tsx` |
| Created | `src/components/MfaVerification.tsx` |
| Created | `src/services/mfa.ts` |
