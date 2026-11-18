# Testing read-only panels

The Testing details and recommendation drawers use persisted execution data.
Host discovery does not establish open ports, services or versions. Missing
values stay unavailable; no follow-up execution is enabled by these panels.

## Original output

`GET /api/v1/assessments/{assessment_id}/testing/executions/{execution_id}/evidence/{evidence_id}/output`

The endpoint requires an active Security Analyst session and assessment access.
It binds the evidence to the same execution, attempt, target and assessment.
The response is JSON with inert UTF-8 text, never an HTML response or storage
path. Output is fetched only after opening Original Tool Output. No execution
or scheduling occurs. Responses use the application's no-store and nosniff
headers. No migration or additional database privileges are required.

Reads enforce the original-output limit of 10 MiB, exact byte length and stored
SHA-256 integrity. Unsupported encodings and missing/corrupt output produce a
controlled unavailable state. The metadata endpoint can describe larger
historical evidence, but this output reader will reject it.

Inline evidence works without filesystem configuration. File-backed evidence
requires an explicit `UPTIP_EVIDENCE_READ_DIRECTORY` pointing to the existing
private evidence directory. It is disabled by default. Every path component is
opened without following symlinks. Only opaque writer-generated `evidence/`
keys with 32 lowercase hexadecimal characters are accepted. The root must be
private and owned by the current process user; files must be private regular
files owned by that user, with one hard link. Reads are bounded and verified.

Do not change worker ownership, grant the API broader filesystem permissions,
or run the API as root to enable this feature. If worker and API OS identities
are isolated, keep file retrieval unavailable. A separately reviewed mediated
read service would be needed for that deployment. No such service is added here.

## Recommendations

The recommendation list enriches source-test metadata using one joined query
scoped to the assessment and the observation/evidence/execution bindings.
Internal identifiers remain in the API for traceability, not the visible drawer.

Alternative selection calls the existing eligibility and authorization-review
GET endpoints. Both remain fail-closed; profiles are empty and all execution
and authorization booleans remain false. An informational review fingerprint is
never used as a token. Unsupported, malformed, stale and unavailable checks
cannot enable Start Test or Confirm Alternative.

## Verification limits

Browser comparison is required at 1440px and a narrow viewport before visual
acceptance. Automated DOM tests do not prove computed layout. This environment's
Chromium launch fails because socket creation is prohibited; the supported cloud
browser also could not connect to the workspace's loopback app. No live Kali
browser or operational database was used. Disposable PostgreSQL 16.2 was used
for integration tests; PostgreSQL 18 verification remains a Kali follow-up.


## Outstanding-validation follow-up

The 15 formerly excluded cases now execute unchanged through an opt-in test-only
administration adapter. The normal restricted sudo-helper path is retained.
`UPTIP_DISPOSABLE_ADMIN_URL` must identify a loopback PostgreSQL admin connection
whose `postgres` database carries the exact `UPTIP disposable test cluster`
comment. The base test database must be owned by `uptip` with its existing test
marker. Only generated `uptip_test_schedule_<32 hex>` databases can be created
or dropped; drop also verifies their owner and marker. Runtime and migration
identities stay separate. No application route imports this adapter.

Required test privileges: the disposable cluster admin creates/drops databases;
`uptip` owns test schemas and has CREATEROLE for the least-privilege worker-role
regression. It does not require SUPERUSER. `uptip_runtime` remains restricted.
The individual migration/concurrency tests start at 0017 and exercise their own
upgrade/downgrade paths. The base integration database is migrated to head.

### PostgreSQL 18 verification on Kali

Run after importing these changes, as your ordinary Kali user, from the frontend
repository. This starts a NEW private cluster on port 55486. It never connects
to the operational server on port 5432. Do not substitute the operational URL.
The trap stops only this newly initialized cluster; its temporary directory is
retained for inspection. If port 55486 is occupied, startup fails safely.

```bash
cd ~/ANTIC_Project/UPTIP/frontend
source ../.venv/bin/activate
bash <<'SH'
set -euo pipefail
PG_BIN=/usr/lib/postgresql/18/bin
"$PG_BIN/postgres" --version | grep -E 'PostgreSQL\) 18\.'
TEST_ROOT=$(mktemp -d /tmp/uptip-pg18-validation.XXXXXXXX)
chmod 700 "$TEST_ROOT"
trap '"$PG_BIN/pg_ctl" -D "$TEST_ROOT/data" -m fast -w stop >/dev/null 2>&1 || true' EXIT
"$PG_BIN/initdb" -D "$TEST_ROOT/data" -U postgres -A trust
"$PG_BIN/pg_ctl" -D "$TEST_ROOT/data" -l "$TEST_ROOT/server.log" \
  -o "-h 127.0.0.1 -p 55486 -c unix_socket_directories=''" -w start
"$PG_BIN/psql" -h 127.0.0.1 -p 55486 -U postgres -d postgres -v ON_ERROR_STOP=1 <<'SQL'
COMMENT ON DATABASE postgres IS 'UPTIP disposable test cluster';
CREATE ROLE uptip LOGIN NOSUPERUSER NOCREATEDB CREATEROLE NOBYPASSRLS;
CREATE ROLE uptip_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE DATABASE uptip_test_readiness_fix OWNER uptip TEMPLATE template0;
COMMENT ON DATABASE uptip_test_readiness_fix IS 'UPTIP disposable integration test database';
SQL
export UPTIP_ENVIRONMENT=test UPTIP_PUBLIC_ORIGIN=https://testserver UPTIP_COOKIE_SECURE=true
export UPTIP_RATE_KEY=isolated-test-only-not-a-deployment-key-123456
export UPTIP_DATABASE_URL=postgresql+psycopg://uptip_runtime@127.0.0.1:55486/uptip_test_readiness_fix
export UPTIP_MIGRATION_DATABASE_URL=postgresql+psycopg://uptip@127.0.0.1:55486/uptip_test_readiness_fix
export UPTIP_TEST_DATABASE_URL="$UPTIP_MIGRATION_DATABASE_URL"
export UPTIP_DISPOSABLE_ADMIN_URL=postgresql+psycopg://postgres@127.0.0.1:55486/postgres
export PYTHONPATH="$PWD/backend"
(cd backend && python -m alembic upgrade head)
python -m pytest -q \
  backend/tests/test_disposable_postgres.py \
  backend/tests/test_testing_reads.py \
  backend/tests/test_recommendation_planner.py \
  backend/tests/test_recommendation_eligibility.py \
  backend/tests/test_recommendation_authorization_review.py \
  backend/tests/test_recommendation_authorization_schema.py \
  backend/tests/test_execution_orchestration.py \
  backend/tests/test_scheduling_start.py
printf 'Disposable cluster files retained at %s\n' "$TEST_ROOT"
SH
```

Trust authentication is restricted to this temporary loopback-only cluster,
which contains synthetic test data and is stopped after the command. No `.env`
files, persistent roles, or operational data are changed.

### Browser acceptance on Kali

Use the existing development configuration; do not start an execution worker,
create new scan jobs, or change integration availability for this check.
In terminal 1:

```bash
cd ~/ANTIC_Project/UPTIP/frontend
source ../.venv/bin/activate
uvicorn app.main:create_app --factory --app-dir backend --reload --host 127.0.0.1 --port 8000
```

In terminal 2:

```bash
cd ~/ANTIC_Project/UPTIP/frontend
npm run dev
```

Open `http://localhost:5173`, sign in normally, and open an already accessible
assessment with persisted results at
`/analyst/assessments/<assessment-id>/testing`. These steps only read existing
records. Do not insert fake observations into the development database.

At 1440x900 and 100% browser zoom, compare each panel with the approved Figma:

1. T-02 (357:151): Test Activity -> View Details for an existing completed
   discovery. Test Details is a right drawer, 490px wide, beginning below the
   64px app header. Selected Test shows the persisted state/tool/target. Results
   show actual responding/nonresponding hosts, not sample ports or versions.
   Original Tool Output and Technical Details begin collapsed. Expand/collapse
   with mouse and keyboard. Output is fetched only when expanded and remains
   inert text. Check scrolling, Escape/Close, and restored trigger focus.
2. T-04B (421:362): Recommendations tab. Verify actual count, Pending Review
   badge, Target/Service/Port columns and right-aligned blue Review Suggestion
   button. Null service/port values read Not identified. An empty list remains
   an empty state; an API error is not reported as an empty list.
3. T-04C (429:257): Review Suggestion. Verify Selected Suggestion, Suggestion
   Information, Why Is This Suggested?, Source Test and Proposed Test in order.
   Source metadata must match the persisted source execution; no prominent raw
   UUIDs. Start Test stays disabled. Footer remains visible as the body scrolls.
4. T-04E (457:308): Choose Alternative. Verify Current Recommendation, Select
   Alternative, Selected Test and Compatibility Status. No invented options.
   Existing GET checks lead to Unavailable; Confirm Alternative stays disabled.
   Cancel returns to review; closing restores focus.

Repeat at 390x844 (responsive device mode), checking no horizontal overflow,
readable columns, scrollable body, reachable close controls and footer buttons.
The narrow drawer fills the viewport; desktop styling remains unchanged.
Check running/failed/queued records where already available: none may be shown
as completed or as having discovered ports. Unavailable private output must
remain a truthful error, not an excuse to loosen worker permissions.

In Network, verify requests use the expected assessment/execution IDs and are
GETs. The output response is JSON with Cache-Control: no-store and
X-Content-Type-Options: nosniff. Do not share cookies, tokens or original output
containing sensitive assessment data. Record screenshots of each panel at each
viewport for final visual acceptance.

### Formerly excluded cases (all passed on the disposable cluster)

```text
backend/tests/test_execution_orchestration.py::test_concurrent_workers_claim_once[empty]
backend/tests/test_execution_orchestration.py::test_dispatch_locks_tool_updates_and_insertions[False-empty]
backend/tests/test_execution_orchestration.py::test_dispatch_locks_tool_updates_and_insertions[True-empty]
backend/tests/test_execution_orchestration.py::test_worker_migration_roundtrip_and_public_denial[empty]
backend/tests/test_execution_orchestration.py::test_migration_refuses_removing_recorded_process_protection[empty]
backend/tests/test_scheduling_start.py::test_scheduling_concurrency[none-True]
backend/tests/test_scheduling_start.py::test_scheduling_concurrency[none-False]
backend/tests/test_scheduling_start.py::test_scheduling_concurrency[scope-True]
backend/tests/test_scheduling_start.py::test_scheduling_concurrency[target-True]
backend/tests/test_scheduling_start.py::test_scheduling_tool_writer_waits_for_confirmation_commit[False]
backend/tests/test_scheduling_start.py::test_scheduling_tool_writer_waits_for_confirmation_commit[True]
backend/tests/test_scheduling_start.py::test_testing_overview_stays_on_one_snapshot_during_scheduling
backend/tests/test_scheduling_start.py::test_existing_creation_and_target_duplicate_races[creation-empty]
backend/tests/test_scheduling_start.py::test_existing_creation_and_target_duplicate_races[target-empty]
backend/tests/test_scheduling_start.py::test_draft_survives_migration_cycle_and_testing_prevents_downgrade
```

Final workspace checks: 101 selected backend tests passed (0 failed, skipped,
deselected or blocked), including the 15 above and administration safety guards;
128 frontend tests passed. ESLint, TypeScript/build, Python compilation and Git
diff validation passed. One nonblocking Starlette/httpx deprecation warning.
These are selected backend regressions, not a claim that every backend suite
was executed. PostgreSQL 18 and actual-browser acceptance remain pending.
