# ANTIC UPTIP

React + TypeScript + Vite frontend at the repository root. Authentication backend:
Python FastAPI, SQLAlchemy, PostgreSQL and Alembic in `backend/`.

The first screen remains the approved Login Default (Figma `44:2587`). Login now
calls the real authentication API. It does not navigate to a dashboard or implement
MFA / password replacement screens.

See [Authentication setup and security contract](docs/authentication.md) for Kali
Linux setup, account provisioning, API states, tests and deployment requirements.

```bash
npm ci
npm run dev
```

Use the backend setup instructions before submitting the form.
