# Explicit scoped service discovery during Start (historical version 1)

> Superseded for new assessments by [automatic service baseline](automatic-service-baseline.md).
> The manual-port workflow below describes the earlier implementation, not the current UI.

This additive path reuses Start Assessment and the existing service-discovery
worker/consent pipeline. It introduces no new Testing screen or automatic tool
approval. It does not alter previously authorized execution snapshots.

## Workflow

1. In a Draft assessment's existing Authorized Scope form, add or edit an exact
   IPv4 entry and enter an optional comma-separated list of authorized TCP ports.
   Up to 16 unique ports in 1–65535 are allowed. No ports are defaulted. Subnet,
   hostname and URL entries cannot authorize TCP service discovery.
2. Add the target through the existing target workflow. Nmap must be enabled with
   both `ipv4-discovery` and `tcp-service-discovery`. Reconcile baseline state
   through the existing tool maintenance workflow if its revision changed.
3. The existing Start confirmation lists Network Discovery and Service Discovery,
   including the latter's exact target and port list. A signed review binds these
   facts, current baseline/tool revisions and the scope revision. Changes require
   a fresh review and explicit confirmation.
4. Start atomically records the review, changes Draft to Testing and creates the
   host and service Queued requests plus the immutable service consent/event.
   Existing replay returns the original receipt, without duplicate scheduling.
5. The service worker cannot dispatch until the associated host request has
   Completed. Pending dependencies leave the request Queued without an attempt;
   unsuccessful dependencies remain blocking. It still verifies current scope, creator permissions, pinned tool,
   exact restricted parameters, independent dispatch policy, ownership, runtime
   safety and consent expiry/revocation. Queued is not Running.
6. Actual successfully processed service XML can generate evidence-backed Nikto
   proposals in the existing Recommendations view. Nikto and OWASP ZAP remain
   non-executable. Host reachability alone cannot produce those proposals.

No authorized ports means the historical host-only path. Missing service
capability excludes that activity and makes a host-only confirmation Partial;
its exclusion is recorded. No existing Testing assessment is silently rescheduled.
The previous explicit service scheduling API remains compatible with its own
separate target-and-port confirmation; it does not retrofit old Start consent.

## Security and persistence

`uptip-scoped-service-scheduling` version 1 is a release-owned scheduling policy
bound to the existing service-discovery dispatch policy digest. It accepts only
the existing constrained profile, not arbitrary CLI arguments. Scheduling facts
are not independent execution evidence or organizational approval.

Migration **0025**, following unchanged 0024, adds `scope_entries.tcp_ports` with
an empty default and database bounds/type-of-scope constraints. Scope changes
retain the existing creator/Draft/Origin/CSRF/revision checks and append before/
after audit facts. Downgrade refuses to erase any recorded TCP-port history.
No runtime grants or scanner installation are changed. Start takes a creator
NO KEY UPDATE lock before the assessment lock, avoiding shared-lock upgrades
when the existing consent trigger locks the creator. Concurrent scope changes
still serialize on the assessment and invalidate previously issued reviews.

The existing service consent lifetime remains one hour from confirmation;
expiry/revocation fails closed. This change does not add renewal or recovery.
Existing v1/v2 requests and historical receipts remain unchanged.

## Verification and Kali acceptance

Automated tests use disposable PostgreSQL and fake adapters only. Migration 0025
must be reviewed, backed up and applied separately on Kali; do not run the new
application against a schema still at 0024. No operational database was migrated
in this implementation.

After controlled deployment, use a newly configured Draft assessment with an
explicitly authorized isolated IPv4 target and ports. Check the Start review,
Queued request identities and persisted Recommendations data. Running an actual
scanner requires separate authorization for that isolated environment. Browser
and PostgreSQL 18 acceptance are separate from workspace automated tests.

### Workspace verification

- Python 3.12 / disposable PostgreSQL 16.2: **337 passed**, no failures or skips.
  Covered scoped Start, existing Start/scope, service discovery, orchestration,
  planner/eligibility/review, completion contracts/concurrency, dispatch,
  plan revalidation, restricted adapter and execution persistence.
- New cases include exact port review/readback, invalid ports, missing capability,
  stale reviews, rollback, concurrent identical/different idempotency keys racing
  with port edits, fake-worker XML → real planner, no scanner/network calls,
  deferred host dependency and downgrade refusal with port history.
- Frontend: **277 passed**; ESLint, TypeScript/production build, Python compilation
  and `git diff --check` passed.
- Existing backend warnings: Starlette/httpx deprecation and pytest attempting
  collection of imported `TestingCompletionEvent`. Test setup also emits a
  platform runtime-directory warning; npm emits an environment proxy warning
  and Vitest a test-environment performance advisory.
- PostgreSQL 18.4 and real-browser/Figma acceptance have **not** been verified.
