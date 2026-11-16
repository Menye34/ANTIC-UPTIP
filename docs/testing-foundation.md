# Phase 3.1 Testing foundation

Verified source: the complete Phase 2 bundle with SHA-256
`c98da00cd25640821207d44b684a7b5ae09954d7a1893a6473f3e7ef6fe43eb4`.
The Phase 2 branch was fast-forwarded to
`dba8997bd7ef31358dabf213be499381a173a5de` before creating
`feat/phase3-testing-foundation`. No earlier implementation was reconstructed.

## Interface and navigation

Figma file `fS3rgXNJDzShoqjctxKhDp` was inspected through design context and
screenshots for T-00 `920:367` and T-01 `357:25`. The implementation reuses
AnalystShell, the local Inter fonts, the card/button conventions and matching
navigation assets. Four assets are exported from the inspected frames: the
white shield, Plus, Information and Marker. Shared T-00/T-01 assets were compared;
the shield differs only in internal clip-path identifiers, with identical
geometry and colors. Root SVG dimensions are preserved.

The authenticated route is `/analyst/assessments/{id}/testing`. Dashboard session
verification remains the gate for direct URL access and refresh. Session/user
identity and assessment-path changes remount and abort the previous page.
Administrators do not gain analyst route access.

A validated successful Testing Start receipt invokes the existing application
navigation. A failed/uncertain response never navigates or resubmits. If the
navigation callback fails after confirmation, the persisted Testing presentation
and native Go to Testing link remain available; navigation failure cannot turn
a successful Start into another write. Existing Testing assessments also have
a working Go to Testing link.

T-00 displays zero cards only after a successful no-executions response. Queued
records use T-01, contribute to Total Tests and do not inflate In Progress.
Every supported request status is rendered. The current status, table, context
cards and minimal read-only details use actual API data. Manual testing,
Recommendations, Testing Completion and Audit Log actions are visibly unavailable
through disabled controls and explanatory titles. No later-phase workflow is
simulated. The empty-state copy does not instruct users to use an unavailable
manual-test action.

## Existing API contracts

Only the existing GET overview and execution-details endpoints are called:

- `/api/v1/assessments/{id}/testing`
- `/api/v1/assessments/{id}/testing/executions/{execution_id}`

The existing executions-list endpoint remains unchanged and can be used later;
the overview already returns all activity rows, so no redundant list fetch is
needed. Requests reuse the existing same-origin, no-store and timeout helper.
Response identity, supported states, nonnegative integer counters, unique rows
and status/count agreement are validated. Read-only data never grants dispatch
permission or enables a new execution action.

Polling waits five seconds after completion of the previous request; requests
cannot overlap. Unmount, account changes, route changes and retries abort the
old request and clear its timer. A refresh outage preserves clearly labelled
last-retrieved data instead of fabricating an empty assessment. 401 invokes the
existing session-expired flow; 403/404 remove cached assessment data. The details
view aborts stale requests and exposes only the existing protected summaries.

Truthful API limitations compared with Figma's example content:

- Scope revision is supplied; human-readable scope boundaries and the Start
  actor's display name are not. These fields say unavailable rather than using
  assessment creation identity or invented boundaries.
- No open-port, service or web-target totals are supplied. The three design
  slots display unavailable markers; actual host observations appear when present.
- Recent Activity currently supplies queue events, so the UI does not invent
  scanner-start, completion or recommendation events.
- Execution details provide attempt/processing outcomes and evidence metadata,
  not raw scanner output. The view states that limitation.
- Request Running counts are not percentages or proof of scanner success.
  RecoveryRequired and processing outcomes are visible in recorded attempt details.

No backend, worker, scheduling rule, database model or migration was changed.
The existing Phase 2 schema/API must already be deployed under its separately
approved migration procedure for live verification. Importing this branch must
not automatically migrate the operational database.

## Verification

- Frontend: **113 tests passed** across 8 files.
- ESLint: passed.
- TypeScript and Vite production build: passed; main JavaScript approximately
  315.47 kB, gzip 92.53 kB.
- Git diff validation: passed.
- Phase 2 regression: **128 passed**, one existing Starlette/httpx deprecation
  warning, against fresh disposable PostgreSQL 16.2 databases created with
  TEMPLATE template0. Python was 3.12.14; Kali PostgreSQL 18/Python 3.13 rerun
  remains separate. No test database was the operational uptip database.

The backend regression command was:

```bash
python -m pytest backend/tests/test_execution_orchestration.py \
  backend/tests/test_nmap_adapter_v2.py backend/tests/test_execution_persistence.py \
  backend/tests/test_scheduling_start.py -q
```

It requires the repository's positively identified disposable test database and
separate migration/runtime identities. Never point it at operational uptip.

Frontend verification commands:

```bash
npm test -- --run
npm run lint
npm run build
git diff --check
```

Tests cover authenticated direct routing/remount, cross-role denial, account
switching, success and failed navigation, uncertain Start outcomes, original
CSRF/idempotency/expiration behavior, loading/empty/error/retry, every supported
request status, mixed counters, details, polling serialization and cleanup.
API fixtures live only in test files and are not imported by the application.

Browser visual verification remains pending: the available Chromium launch
failed because the managed environment disallows its Unix socket. The Figma
references and exported assets were inspected, but no rendered pixel comparison,
effective browser geometry check or live API/browser acceptance is claimed.
No real scanner was executed; controlled synthetic subprocess tests are not live
scan verification. On Kali, check both Figma states at 1440px, then refresh a
Testing URL and verify persisted queue/status changes through the actual APIs.

## Changed files

Routing/integration: App.tsx, components/AnalystShell.tsx,
components/AssessmentPage.tsx, components/AssessmentTargets.tsx,
services/assessmentStart.ts and services/assessments.ts under src/.

Added: src/components/TestingPage.tsx, TestingPage.css and TestingPage.test.tsx;
src/services/testing.ts; src/TestingRoute.test.tsx; src/test-fixtures/testing.ts;
four SVGs under src/assets/testing/; and this document.

Updated regression expectations: src/components/AssessmentPage.test.tsx and
src/components/AssessmentTargets.start.test.tsx. No existing tests were deleted
or disabled.
