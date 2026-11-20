# Automatic baseline and Figma Testing corrections

## What is corrected

- Preserve the existing Start confirmation and approved automatic TCP 80/443
  preparation. Remove the extra Testing service-scheduling card and manual scope
  port field. Existing narrower port boundaries are retained and respected.
- T-01 retains the four metric cards, status notice, table and three context cards.
  Scope boundaries and the actual Start actor/time are read from persisted state.
  Discovery counts use completed successful processing and nonpartial provenance,
  deduplicated by target/address/port. Unknown values are shown as unavailable,
  not zero. An HTTP service does not prove a web application.
- T-02 is a right-side drawer matching the existing 490px review drawer geometry.
  Recorded services populate Port / Service / Version columns. No port, service
  or version is copied from Figma examples. Original Tool Output and Technical
  Details are collapsed by default. Current execution/processing changes refresh
  sequentially; verified terminal work stops polling. Unknown/recovery states do
  not become success. Refresh preserves disclosures, scroll and focus; closure,
  navigation and access denial abort/discard obsolete requests.
- T-04C uses Review Recommendation, Recommendation Information, Why is this
  recommended?, Source Test, Proposed Test, Proposed Tool and Test Description.
  Accept is the primary footer action alongside Reject and Choose Alternative.
  The header close action remains available. Accept records review only.
- T-04E remains read-only/unavailable where no integrated, authorized alternative
  exists. No Manual Testing, Findings, Nikto, ZAP or new execution controls.

Figma references: file `fS3rgXNJDzShoqjctxKhDp`, frames T-01 `357:25`, T-02
`357:151`, T-04C `429:257`, T-04E `457:308`. Dynamic names, versions and counts
come from backend state and may differ from the design's example content.

## API and safety

Existing Testing endpoints remain compatible; added overview fields:

- `authorization_scope.boundaries`, `scope_current`, `authorized_by` (ID,
  username, confirmation timestamp). A mismatched current scope digest/revision
  does not masquerade as the reviewed boundary.
- `discovery_totals`: `open_ports`, `services`, `web_targets` (nonnegative integers
  or null when the available evidence does not establish the metric).

Overview and Execution Details project access and related data in one PostgreSQL
statement. A concurrency test commits a fake worker update while a details read
is in progress and verifies that old request state cannot mix with new attempts.

Protected read-only endpoint:

`GET /api/v1/assessments/{assessment_id}/testing/executions/{execution_id}/evidence/{evidence_id}`

It verifies assessment access and request/attempt/evidence/target relationships;
returns exact UTF-8 text plus identity, format, size, partial flag and SHA-256;
limits evidence to 10 MiB; and verifies byte length and SHA-256 before display.
The frontend renders escaped text in a PRE element, never executable XML/HTML.
Invalid UTF-8/binary content is unavailable for this text view and stays preserved.
Unauthorized, cross-assessment or unrelated evidence is not returned. Paths,
storage keys, worker process identities and signing/session secrets are not exposed.
All responses retain Cache-Control: no-store. No scanner calls or database writes.

Small inline evidence requires no additional configuration. File-backed evidence
requires server-only `UPTIP_EVIDENCE_READ_DIRECTORY` pointing to the existing
worker EvidenceStore root. It must be absolute, private (0700) and owned by the
backend OS account, consistent with the existing private store. Each path
component is opened without symlink traversal; opaque evidence keys only; files
must be private regular single-link files of the expected size and owner. Missing
configuration, OS access or integrity failures fail closed. Do not broaden
filesystem permissions to make the view work. Separate worker/backend OS users
need a separately reviewed read-only evidence-access arrangement; no such service
or privilege changes are introduced here.

## Migration and history

No migration is added or modified. Migration 0025, immutable Start/completion
history, original evidence, scope entries and existing queued requests remain
unchanged. Start audit and linked immutable consent provide scheduling provenance;
the web role does not need worker-history INSERT or worker-lock EXECUTE privileges.
Old v1 consent definitions and receipt replay remain supported. Previously started
assessments are not automatically rescheduled. The original uncertain manual
request is not retried or assumed failed by removal of its UI.

## Verification

- Relevant backend regression suites: **361 passed**, no failures or skips, using
  Python 3.12 and a marked disposable PostgreSQL 16.2 cluster. Includes automatic
  Start under restricted runtime permissions, historical compatibility, baseline
  concurrency, fake Nmap processing, real planner/review integration, completion
  gates, evidence authorization/integrity/filesystem attacks, and coherent reads.
- Full frontend suite: **295 passed**. TypeScript, ESLint, production build,
  Python compilation and Git diff checks passed.
- Existing warnings: Starlette/httpx deprecation and pytest model collection;
  test cluster runtime-directory warning; npm proxy configuration warning; Vitest
  environment-performance advisory.
- Actual browser acceptance is NOT claimed. A sandboxed Chromium launch failed
  before a page opened. No sandbox-disable workaround was attempted. Figma
  source/layout comparison and DOM/interaction tests are not pixel-perfect proof.
- PostgreSQL 18.4 and actual Kali browser verification remain required.

## Kali acceptance (after verified bundle import)

No additional operational migration is required when Alembic current is 0025.
Keep backups and immutable history; do not reset the operational database.

Deploy backend and worker from the same imported commit. A long-running worker
will not reload its Python modules merely because Git files changed. Before new
Start confirmations, use the established controlled shutdown/restart procedure
when existing attempts are settled, and verify that the updated worker is running.
An old worker does not understand scheduling policy v2 and must fail closed;
do not leave it processing new-version requests. Do not interrupt active scans
or automatically retry blocked requests as part of importing this bundle.

Frontend verification:

```bash
npm test -- --run
npm run lint
npm run build
```

For PostgreSQL 18.4 tests use the separate marked disposable cluster procedure in
`docs/phase3-integration.md`, never the operational `uptip` database. Relevant
additional suites are:

```bash
python -m pytest -q backend/tests/test_testing_read_projection.py \
  backend/tests/test_automatic_service_start.py backend/tests/test_scoped_service_start.py \
  backend/tests/test_scheduling_start.py backend/tests/test_service_discovery.py \
  backend/tests/test_scope.py backend/tests/test_execution_orchestration.py \
  backend/tests/test_intelligent_planner.py backend/tests/test_recommendation_planner.py \
  backend/tests/test_recommendation_eligibility.py backend/tests/test_recommendation_authorization_review.py \
  backend/tests/test_testing_completion.py backend/tests/test_testing_completion_contract.py \
  backend/tests/test_testing_completion_concurrency.py backend/tests/test_nmap_dispatch_authorization.py \
  backend/tests/test_nmap_plan_revalidation.py backend/tests/test_nmap_adapter_v2.py \
  backend/tests/test_execution_persistence.py
```

Start application processes in separate terminals:

```bash
source .venv/bin/activate
uvicorn app.main:create_app --factory --app-dir backend --reload --host 127.0.0.1 --port 8000
# Separate terminal, same repository:
npm run dev -- --host 127.0.0.1 --port 5173
```

1. Sign in and open Testing for an existing assessment. No supplemental scheduling
   card should appear. Check four request metrics and the context cards. Original
   host-only assessments legitimately have no identified services/recommendations.
2. Open View Details. Compare the right drawer to T-02 at desktop and narrow
   widths. Check scroll, close/Escape/focus restoration and collapsed disclosures.
   Expand Original Tool Output only for authorized evidence; it must appear as
   text, with partial/unavailable states truthful. Test worker-dependent states
   only with approved fixtures/isolated targets.
3. For a genuinely authorized isolated target, use a fresh Draft assessment with
   current Nmap capabilities. Review automatically prepared TCP 80/443 before
   Start. Do not confirm unless execution is authorized: an active worker may
   immediately process newly Queued requests. Queued never means Running.
4. When actual complete HTTP/HTTPS evidence exists, review the planner's Nikto
   proposals through T-04C. Verify source, explanation, proposed tool, footer and
   persisted review after refresh. No HTTP/HTTPS evidence means no invented
   recommendation. Nikto/ZAP execution stays unavailable.
5. Check T-04E's unavailable alternatives and existing completion safeguards.
   Do not enable unsupported controls to imitate the Figma example states.
