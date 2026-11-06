# ANTIC UPTIP

React + TypeScript + Vite frontend at the repository root. Authentication backend:
Python FastAPI, SQLAlchemy, PostgreSQL and Alembic in `backend/`.

The first screen remains the approved Login Default (Figma `44:2587`). Login now
calls the real authentication API and conditionally opens First Login or the
configured MFA Verification step. Dashboard navigation is not implemented.

See [Authentication setup and security contract](docs/authentication.md) for Kali
Linux setup, account provisioning, API states, tests and deployment requirements.

```bash
npm ci
npm run dev
```

Use the backend setup instructions before submitting the form.

[MFA Verification development setup](docs/mfa-verification.md) documents the
five Figma states, real TOTP challenge flow, explicit development harness and
unresolved production-policy dependency.

[First Login password replacement](docs/first-login.md) covers the restricted
challenge, migration, Figma states and localhost verification commands.
