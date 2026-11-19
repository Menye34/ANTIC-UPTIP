# Phase 3 Testing integration stabilization

Base: `integration/phase3-stabilization-sync` at
`e38124f81a3b79c38e08a31b4c09a6f636eab807`.

## Root causes and correction boundary

The integration imported the recommendation/completion backend and completion
component/service but left both tabs disabled in the actual TestingPage. The
page had no recommendation reads, no completion-component mount or durable
parent operation state, and did not receive the session CSRF token. Its Testing
response validator and Assessment type also omitted `Finding Review`, causing
post-completion reloads to reject a valid lifecycle.

This correction adds those integration points using the existing components,
contracts and recommendation review design. It retains the base branch's Test
Activity markup, status-specific Execution Details and event timeline. It does
not replace the page wholesale, register duplicate routers, implement Findings,
change scanner/worker logic, add recommended-test dispatch or alter safety gates.
Start Test, Confirm Alternative and Manual Testing remain unavailable.

Completion and decision POSTs retain backend session, role, Origin, CSRF and
assessment-access enforcement. Only the creator may complete; assigned analysts
may review and record recommendation decisions. Deferred decisions remain
blocking. The validated completion snapshot is authoritative; confirmation binds
to its captured digest. Ambiguous POST outcomes use authenticated GET readback,
never automatic POST retries. Parent state preserves uncertainty across tab
switches. Only a valid persisted receipt establishes completed status.

Recommendation cards and dialogs show persisted decisions separately from
execution eligibility. The total badge is not a pending-decision count. Reads
are aborted when obsolete and generation checks prevent old data replacing a
new decision. No UI mount or dialog opening writes a decision. The backend
currently returns `followup_profile_not_supported`; this is a legitimate lack
of executable follow-up capability, not a reason to enable Start Test.

## Backend and migrations

The imported production backend modules needed no changes after API and
concurrency regression verification. Existing endpoints are exercised through
TestClient rather than inferred from FastAPI router internals.

The chain is `0019 -> 0020 -> 0021 -> 0022`. No migration history is edited and
no new migration is added. An isolated test upgrades an existing Draft
assessment through each revision, checks foreign keys/triggers and compares
current SQLAlchemy metadata at head. History tests cover immutable completion
receipts, deletion/TRUNCATE protections, downgrade refusal and runtime grants.
The owner/superuser remains a privileged boundary; production runtime roles must
not own tables or possess DDL/superuser privileges.

Historical migration tests must use the revision they test. The 0019 protection
test now starts at 0019, and the 0018 model comparison excludes only the four
tables introduced in 0020/0021; full metadata equality is checked at 0022.
Test-only direct administration requires a loopback destination, exact roles,
database names, matching ports and both database and cluster opt-in markers.
Each committed/concurrency test gets a fresh database. Existing restricted-helper
and CI paths remain available.

## Safe PostgreSQL 18 Kali verification

Do not run these tests against `uptip`. Use a new, temporary cluster as a normal
non-root user. This does not require stopping or migrating the operational cluster.
The commands below use the existing PostgreSQL 18 binaries and a separate port.
Stop if initdb, startup, identity checks or migrations fail.

```bash
# From the repository root, using its activated test virtual environment:
set -e
PGBIN=/usr/lib/postgresql/18/bin
"$PGBIN/postgres" --version
TEST_CLUSTER=$(mktemp -d /tmp/uptip-phase3-test.XXXXXXXX)
chmod 700 "$TEST_CLUSTER"
"$PGBIN/initdb" -D "$TEST_CLUSTER/data" -A trust -U postgres
trap '"$PGBIN/pg_ctl" -D "$TEST_CLUSTER/data" -m fast -w stop' EXIT
"$PGBIN/pg_ctl" -D "$TEST_CLUSTER/data" -l "$TEST_CLUSTER/server.log" \
  -o "-h 127.0.0.1 -p 55486 -c unix_socket_directories=''" -w start
"$PGBIN/psql" -h 127.0.0.1 -p 55486 -U postgres -d postgres -v ON_ERROR_STOP=1 <<'SQL'
COMMENT ON DATABASE postgres IS 'UPTIP disposable test cluster';
CREATE ROLE uptip LOGIN CREATEROLE;
CREATE ROLE uptip_runtime LOGIN;
CREATE DATABASE uptip_test_readiness_fix OWNER uptip TEMPLATE template0;
COMMENT ON DATABASE uptip_test_readiness_fix IS 'UPTIP disposable integration test database';
SQL
export UPTIP_ENVIRONMENT=test UPTIP_PUBLIC_ORIGIN=https://testserver
export UPTIP_RATE_KEY=synthetic-test-only-not-for-deployment-123456
export UPTIP_DATABASE_URL=postgresql+psycopg://uptip_runtime@127.0.0.1:55486/uptip_test_readiness_fix
export UPTIP_MIGRATION_DATABASE_URL=postgresql+psycopg://uptip@127.0.0.1:55486/uptip_test_readiness_fix
export UPTIP_TEST_DATABASE_URL="$UPTIP_MIGRATION_DATABASE_URL"
export UPTIP_DISPOSABLE_ADMIN_URL=postgresql+psycopg://postgres@127.0.0.1:55486/postgres
unset UPTIP_CI_POSTGRES_ADMIN_URL
(cd backend && python -m alembic upgrade head)
python -m pytest -q \
 backend/tests/test_phase3_integration.py \
 backend/tests/test_testing_completion*.py \
 backend/tests/test_recommendation*.py \
 backend/tests/test_scheduling_start.py \
 backend/tests/test_execution_orchestration.py \
 backend/tests/test_execution_persistence.py \
 backend/tests/test_assessment_start.py \
 backend/tests/test_assessment_readiness.py \
 backend/tests/test_auth.py backend/tests/test_security.py \
 backend/tests/test_nmap_adapter_v2.py backend/tests/test_nmap_dispatch_authorization.py \
 backend/tests/test_nmap_plan_revalidation.py backend/tests/test_nmap_execution_binding.py \
 backend/tests/test_disposable_postgres.py
npm test -- --run
npx tsc -b --pretty false
npm run lint
npm run build
python -m compileall -q backend/app backend/tests
git diff --check
```

Tests use synthetic evidence and fake adapters; do not start an execution worker
or run a real scanner as part of acceptance. Trust authentication above applies
only to a temporary loopback test cluster; never copy it to deployment settings.

## Application/browser acceptance (pending in Kali)

Use the normal, independently verified application configuration in separate
terminals (not the test-cluster environment above):

```bash
uvicorn app.main:create_app --factory --app-dir backend --reload --host 127.0.0.1 --port 8000
npm run dev -- --host 127.0.0.1 --port 5173
```

Sign in and open the selected assessment's existing Testing route. Check:

1. Test Activity still shows real persisted Nmap states, counts, timeline and
   state-specific details. Queued must not be presented as Running.
2. Recommendations: loading/error is distinct from empty; responding-host
   observations produce provenance-linked suggestions. Review and Choose
   Alternative expose read-only limitations; execution buttons remain disabled.
3. Testing Completion: verify creator vs assigned-analyst capability, blockers,
   Deferred/Reviewed persistence and recommendation badge/card refresh.
4. For legitimately complete test data, explicitly confirm completion. Verify
   the persisted Finding Review receipt, reload, and ensure no second completion
   or fabricated Findings navigation appears.
5. Compare the existing recommendation/completion designs visually. Automated
   jsdom tests are not browser or pixel-perfect Figma acceptance.

No live Kali migration has been performed. A deployment at 0022 needs no new
schema revision for this correction. If Kali is older, first verify its revision,
backup and environment and obtain controlled migration approval; do not blindly
run upgrade against the operational database.

## Codex verification results

- 330 selected backend tests passed, zero failures/skips, on a new disposable
  PostgreSQL 16.2 cluster bound to port 55486. This includes authentication,
  legacy/default Start, execution persistence/orchestration, Nmap adapter and
  dispatch safety, recommendations, completion, real concurrency and migrations.
- 228 frontend tests passed; TypeScript, ESLint, Vite production build, Python
  compilation and Git diff validation passed.
- Existing warnings: Starlette/httpx deprecation, pytest attempting collection of
  the imported TestingCompletionEvent ORM class, temporary runtime-directory
  fallback, and npm's environment `http-proxy` configuration warning.
- The legacy Start migration fixture now provisions its synthetic account through
  the privileged setup session and tests API requests through the runtime role.
  Test-only runtime bootstrap grants do not grant table ownership, DDL, TRUNCATE,
  or protected-history UPDATE/DELETE. Rejected downgrades must retain the exact
  starting revision, replacing an obsolete list of previously possible heads.
- No operational database, real scanner, worker process, or production permission
  was modified. No actual Kali/browser or PostgreSQL 18.4 acceptance is claimed.
