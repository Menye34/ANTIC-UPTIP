# ANTIC UPTIP

React + TypeScript + Vite frontend at the repository root. Authentication backend:
Python FastAPI, SQLAlchemy, PostgreSQL and Alembic in `backend/`.

The first screen remains the approved Login Default (Figma `44:2587`). Login now
calls the real username/password authentication API and opens First Login when
temporary-password replacement is required. Dashboard navigation is not implemented.

See [Authentication setup and security contract](docs/authentication.md) for Kali
Linux setup, account provisioning, API states, tests and deployment requirements.

```bash
npm ci
npm run dev
```

Use the backend setup instructions before submitting the form.

[First Login password replacement](docs/first-login.md) covers the restricted
challenge, migration, Figma states and localhost verification commands.
