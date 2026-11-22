# Recommended Nikto execution: guarded integration

## Release status

This change connects the existing recommendation API, queue, worker, result
capture and Testing interface. **It is not an activated Nikto release.**
`nikto_profile.py` version 1 and its digest are unchanged, including
`execution_enabled=False`. Consequently real Start readiness reports
`execution_integration_pending`, Start Test stays disabled and the worker cannot
dispatch Nikto. No approval records or synthetic deployment evidence are created.

The Codex environment lacks nftables, slirp4netns and installed Nikto. Positive
kernel containment and actual Nikto 2.6.1 compatibility therefore remain
unverified. The nine opt-in containment checks below are mandatory before any
activation. A subsequent reviewed, explicitly versioned policy is required;
do not toggle version 1 in place or reinterpret old queued plans. Old jobs with
NULL authorization snapshots fail closed. No automatic retry or supersession is
provided for Blocked, failed or uncertain jobs.

The base inspected was `5fd20fd5781e216860c599785c758bd9a6ba59a6` on
`feat/start-recommended-test`. The attached Testing PDF and Figma T-04D
(`446:283`) informed the existing centered dialog. Actual-browser visual
acceptance, Python 3.13 and PostgreSQL 18 acceptance remain Kali checks.

## What is connected

* Accepted, current evidence-backed Nikto recommendations receive server-derived
  readiness facts: creator, active account/role, current Testing lifecycle,
  target/scope revisions and digest, current acceptance event, source evidence
  and observation, trusted tool revision, exact profile/parameter plan.
* POST Start requires the captured readiness digest, Origin, CSRF and creator
  permission. A one-hour immutable consent snapshot, Queued job and append-only
  event are committed together. Concurrent duplicate requests return one job.
* The same execution worker processes both queues. It locks current inputs,
  checks immutable consent and expiry, rechecks immediately before launch and
  periodically, and persists verified termination/output. An unresolved launch
  stays Running with a recovery-required event and blocks both queues after
  restart. It is never automatically retried or declared terminated.
* Test Activity combines real records from both queues. Recommended jobs never
  inherit baseline authorization IDs or fabricated attempts. Their details show
  real timeline/outcome metadata; original stdout/stderr is retrieved lazily
  through the existing protected evidence URL and verified by size/SHA-256.
* Completed means the scanner process exited successfully with complete,
  integrity-checked captured output. **No normalized Nikto findings processor is
  implemented.** Output is not itself a verified finding. Testing Completion
  therefore retains its missing-processing safety blocker for those jobs.
* The modal uses Cancel and Start Test. It binds confirmation to the displayed
  digest, prevents immediate duplicate submissions, and invalidates changed
  readiness. Lost or malformed responses use authenticated GET receipt readback;
  no POST retry occurs. Inconclusive readback remains uncertain at parent level.

## Scanner contract and containment

Nikto is pinned to 2.6.1. The fixed arguments are:

```
-host IPV4 -port PORT -nointeractive -nocheck -nolookup
-timeout 10 -maxtime 300s -Tuning 123b -Plugins headers;tests
```

HTTPS adds only `-ssl`. There are no analyst-controlled flags, URLs, proxies or
plugins. `-followredirects` is absent. The unsupported former `-noupdate` and
`-noredirect` flags were removed and integer timeout corrected. The 2.6.1 source
was inspected, not an installed executable:

* https://github.com/sullo/nikto/blob/2.6.1/program/plugins/nikto_core.plugin
* https://github.com/sullo/nikto/blob/2.6.1/program/plugins/nikto_headers.plugin
* https://github.com/sullo/nikto/blob/2.6.1/program/plugins/nikto_tests.plugin

The proposed rootless boundary uses the existing supervisor and trusted
root-owned, non-writable distro helpers: `/usr/bin/unshare`, `/usr/bin/nsenter`,
`/usr/bin/slirp4netns`, `/usr/sbin/nft`, `/usr/bin/python3`. It needs libseccomp,
unprivileged user namespaces, a supported x86_64/aarch64 Linux kernel with
`mount_setattr` (5.12+), and permission to create private user/net/mount namespaces.
Missing or untrusted prerequisites fail closed. No host firewall is modified.

The holder makes its mount tree recursively read-only. nftables default-drop
rules permit only the exact IPv4 TCP endpoint, deny IPv6 and all other outbound
traffic. slirp provides rootless connectivity with host-loopback disabled.
Only the scanner child enters pinned namespace FDs. Before exec it drops all
capabilities and their bounding set, locks NOROOT, sets no-new-privileges and
denies namespace/mount escape, raw/UDP/non-IPv4 sockets, Unix socket IPC and
io_uring through seccomp. The worker retains its host network and PostgreSQL
connection. Helpers and scanner are supervised and reaped; unverifiable cleanup
poisons that boundary instead of allowing reuse.

Loopback, unspecified/multicast addresses, TCP 53 and slirp's 10.0.2.0/24 subnet
are unsupported. They are rejected rather than remapped. A local test should use
an explicitly authorized, non-loopback private address assigned to the Kali host.
These mechanisms are implemented but **must not be described as kernel-verified
containment until the real tests pass**.

## Schema and roles

Migration `0027_recommended_test_history.py` follows existing `0026` without
rewriting any history. It adds nullable legacy-safe authorization/termination/
partial/process columns, cross-assessment FK protection and an append-only event
table. Immutable job identity/consent and terminal output cannot be changed;
DELETE and TRUNCATE are rejected. Downgrade refuses if any job/event exists.
Database owners/superusers can bypass DDL protections and must never be runtime
roles. Empty-schema downgrade is a test-only path, not an operational rollback.

`uptip_runtime` receives SELECT/INSERT on jobs/events and a narrow completion
locking helper, not job UPDATE. If `uptip_worker` exists during upgrade it
receives SELECT on required decision/history tables, event INSERT, outcome-only
column UPDATE and a fixed-search-path input-lock helper. PUBLIC execution is
revoked on helpers. Existing runtime grants are not broadened.

The worker role must already have the documented Nmap read/persistence rights;
it must not own protected tables, have DDL/admin powers, or destructive rights.
If provisioning the worker role after migration, the DBA must explicitly grant
the same narrow privileges in `0027`; do not grant ALL or owner membership.
An empty downgrade leaves preexisting-table grants in place; review role grants
separately if removing the integration. No production grants were performed here.

Before upgrading, inspect legacy bindings read-only:

```sql
SELECT j.id FROM recommended_test_jobs j
LEFT JOIN assessment_targets t
 ON t.id=j.target_id AND t.assessment_id=j.assessment_id
WHERE t.id IS NULL;
```

Any row blocks the new FK. Investigate its history; do not delete it to force an
upgrade. Legacy jobs are not backfilled with invented consent or events.

## Safe Kali validation (separate cluster, never `uptip`)

The following starts an isolated PostgreSQL 18 cluster on a separate port. Run as
the ordinary developer, not root. Verify these paths/port first. The commands do
not connect to the operational database. Temporary files are intentionally kept
for inspection; the exit trap stops only the named test cluster.

```bash
cd ~/ANTIC_Project/UPTIP/frontend
source .venv/bin/activate
(
set -eu
test -x /usr/lib/postgresql/18/bin/initdb
test_root=$(mktemp -d /tmp/uptip-nikto-validation.XXXXXX)
pgbin=/usr/lib/postgresql/18/bin
"$pgbin/initdb" -D "$test_root/data" -A trust -U postgres
trap '"$pgbin/pg_ctl" -D "$test_root/data" -m fast -w stop' EXIT
"$pgbin/pg_ctl" -D "$test_root/data" -l "$test_root/server.log" \
  -o '-h 127.0.0.1 -p 55486 -k ""' -w start
"$pgbin/psql" -X -v ON_ERROR_STOP=1 -h 127.0.0.1 -p 55486 -U postgres -d postgres <<'SQL'
CREATE ROLE uptip LOGIN CREATEROLE;
CREATE ROLE uptip_runtime LOGIN;
CREATE DATABASE uptip_test_readiness_fix OWNER uptip TEMPLATE template0;
COMMENT ON DATABASE uptip_test_readiness_fix IS 'UPTIP disposable integration test database';
COMMENT ON DATABASE postgres IS 'UPTIP disposable test cluster';
SQL
export UPTIP_DATABASE_URL=postgresql+psycopg://uptip_runtime@127.0.0.1:55486/uptip_test_readiness_fix
export UPTIP_MIGRATION_DATABASE_URL=postgresql+psycopg://uptip@127.0.0.1:55486/uptip_test_readiness_fix
export UPTIP_TEST_DATABASE_URL="$UPTIP_MIGRATION_DATABASE_URL"
export UPTIP_DISPOSABLE_ADMIN_URL=postgresql+psycopg://postgres@127.0.0.1:55486/postgres
export UPTIP_ENVIRONMENT=test UPTIP_PUBLIC_ORIGIN=https://testserver
export UPTIP_RATE_KEY=test-only-not-a-deployment-secret-123456
export PYTHONPATH=backend
python -m alembic -c backend/alembic.ini upgrade head
python -m pytest -q backend/tests/test_nikto_workflow.py \
  backend/tests/test_nikto_network_boundary.py backend/tests/test_nikto_adapter.py \
  backend/tests/test_nikto_profile.py backend/tests/test_tool_adapter_registry.py
)
npm test -- --run
npm run lint
npm run build
```

The database-dependent positive tests use synthetic policy monkeypatches and fake
scanners only. They do not activate the release or authorize a real scan.

For kernel-only acceptance, explicitly authorize the local listening sockets and
set the private, non-loopback IPv4 address belonging to this host. This test opens
two temporary TCP listeners; it does not run Nikto or scan an external target:

```bash
export UPTIP_NIKTO_CONTAINMENT_TEST=1
read -r -p 'Authorized private IPv4 assigned to this Kali host: ' UPTIP_AUTHORIZED_TEST_IPV4
export UPTIP_AUTHORIZED_TEST_IPV4
PYTHONPATH=backend python -m pytest -q \
  backend/tests/test_nikto_network_boundary.py -k kali_kernel_containment
unset UPTIP_NIKTO_CONTAINMENT_TEST UPTIP_AUTHORIZED_TEST_IPV4
```

All nine scenarios must pass without skip: allowed endpoint, other port, other
IP, DNS, IPv6, firewall modification, namespace escape, read-only filesystem,
and unchanged parent networking. Any failure leaves the release disabled. Also
verify helper cleanup, the actual pinned Nikto installation/config/plugins and
an explicitly approved local end-to-end test in a disposable assessment before
reviewing a new enabled policy version. Do not substitute fixture success for
these checks or run the worker as root.

## Deployment and browser acceptance

1. Import the verified bundle using a clean working tree and fast-forward checks.
   Preserve unrelated files; do not reset or force-update a diverged branch.
2. Run the separate-cluster migration/tests first. Back up operational data and
   stop the existing worker only after current work is known terminated. Do not
   mark a Running/uncertain job completed to permit a restart.
3. During an approved maintenance window, with the migration role configured,
   use `PYTHONPATH=backend python -m alembic -c backend/alembic.ini current`,
   `heads`, then `upgrade 0027`; confirm `current`. No migration was applied to
   Kali by this implementation. Restarting code without the new schema is unsafe.
4. Keep one existing worker service and its Nmap configuration. Optional flags
   are `--nikto-executable`, `--nikto-sha256`, `--nikto-version 2.6.1`, together.
   Pin a trusted root-owned installation and its real hash, not documentation
   placeholders. No Nikto dispatch is enabled by these flags. Missing isolation
   reports Nikto unavailable while Nmap continues. Inspect `--help` before editing
   the existing unit; do not create a second service.
5. After an authorized code/unit update use `sudo systemctl daemon-reload` only
   if the unit changed, then `sudo systemctl restart uptip-execution-worker.service`
   and `sudo journalctl -u uptip-execution-worker.service -n 80 --no-pager`.
   Do not share logs containing credentials/output. Review any recovery-required
   state instead of restarting repeatedly.
6. Browser: accepted recommendation → Start Test → T-04D. Check exact labels,
   server-derived endpoint/profile, correct unavailable state (this release),
   Cancel/focus, stale review, and read-only uncertain status recovery. After a
   separately approved enabled release, verify exactly one queued job appears,
   then Running/terminal state, real timeline and lazy original output. Compare
   layout to Figma; never use sample findings as real results.

No production Nikto launch, production database change, external scan or browser
acceptance was performed in Codex. OWASP ZAP remains unimplemented and unavailable.

## Changed-file index

| File | Purpose |
| --- | --- |
| `backend/app/nikto_network_boundary.py` | Gated rootless namespace/firewall and child confinement launcher. |
| `backend/app/recommended_test_authorization.py` | Reproducible creator/scope/acceptance/tool consent and fresh validation. |
| `backend/app/recommended_testing_reads.py` | Assessment-isolated job projections and integrity-checked original output. |
| `backend/app/baseline_maintenance.py` | Recognize trusted operator Nikto capability without adding an automatic baseline. |
| `backend/app/execution_orchestration.py` | Prevent Nmap dispatch while recommended execution is unresolved. |
| `backend/app/execution_worker.py` | Integrate the existing recommended runner and optional isolated Nikto probe. |
| `backend/app/nikto_adapter.py` | Fixed 2.6.1 invocation and mandatory child boundary. |
| `backend/app/nmap_adapter.py` | Narrow launch-context hook; default Nmap behavior preserved. |
| `backend/app/recommended_test_consumer.py` | Use complete consent revalidation rather than target-only checks. |
| `backend/app/recommended_test_queue.py` | Legacy-safe provenance/outcome columns and event mapping. |
| `backend/app/recommended_test_results.py` | Persist termination/partial state and retain uncertain ownership. |
| `backend/app/recommended_test_runner.py` | Claim once, hold input locks through launch, supervise and audit outcomes. |
| `backend/app/testing_completion_service.py` | Include real recommended jobs and keep completion blocked on unresolved work. |
| `backend/app/testing_routes.py` | Digest-bound Start/readback plus existing Testing API queue integration. |
| `backend/migrations/versions/0027_recommended_test_history.py` | Additive immutable history, relationship and least-privilege protections. |
| `backend/tests/test_nikto_workflow.py` | API, fake worker, authorization, concurrency, history and role regressions. |
| `backend/tests/test_nikto_network_boundary.py` | Negative unit checks and nine explicit Kali kernel acceptance scenarios. |
| `backend/tests/test_nikto_adapter.py` | Correct supported fixed arguments/version fixture. |
| `backend/tests/test_tool_adapter_registry.py` | Pin supported Nikto 2.6.1 fixtures. |
| `backend/tests/test_execution_orchestration.py` | Add required queue SELECT to restricted test role; verify current-head rollback. |
| `backend/tests/test_execution_persistence.py` | Exclude later recommended tables from historical 0018 metadata comparison. |
| `backend/tests/test_scheduling_start.py` | Expect current head after refused downgrade, preserving all history assertions. |
| `backend/tests/test_scoped_service_start.py` | Expect current head after refused downgrade. |
| `backend/tests/test_service_discovery.py` | Expect current head after refused consent-history downgrade. |
| `backend/tests/test_service_dispatch_diagnostics.py` | Guard the current adapter-registry hook against operational diagnostic access. |
| `src/components/ExecutionDetailsDrawer.tsx` | Show truthful recommended outcomes/raw output, not invented service findings. |
| `src/components/StartRecommendedTest.tsx` | Captured preview, duplicate guard, authoritative uncertain readback. |
| `src/components/StartRecommendedTest.test.tsx` | T-04D labels, submission, failures, recovery, abort and duplicate tests. |
| `src/components/TestingPage.tsx` | Parent operation state and refresh; preserve review for non-accepted decisions. |
| `src/components/TestingPage.test.tsx` | Persisted recommended-job status/detail rendering. |
| `src/services/testing.ts` | Validate preview/receipt/result contracts and safe readback. |
| `docs/nikto-recommended-execution.md` | Status, security limitations, migration, test and deployment handoff. |

## Codex verification record

Environment: Python 3.12, disposable PostgreSQL 16.2, no operational database.
The validation harness created a fresh marked cluster, migrated it to head,
ran pytest, then stopped that cluster. Its command was
`.venv/bin/python ../validation/run_tests.py` followed by these exact paths:

```
backend/tests/test_nikto_workflow.py
backend/tests/test_nikto_network_boundary.py
backend/tests/test_nikto_adapter.py
backend/tests/test_nikto_profile.py
backend/tests/test_tool_adapter_registry.py
backend/tests/test_service_dispatch_diagnostics.py
backend/tests/test_testing_read_projection.py
backend/tests/test_automatic_service_start.py
backend/tests/test_scoped_service_start.py
backend/tests/test_scheduling_start.py
backend/tests/test_baseline_scheduling.py
backend/tests/test_service_discovery.py
backend/tests/test_scope.py
backend/tests/test_execution_orchestration.py
backend/tests/test_intelligent_planner.py
backend/tests/test_recommendation_planner.py
backend/tests/test_recommendation_eligibility.py
backend/tests/test_recommendation_authorization_review.py
backend/tests/test_testing_completion.py
backend/tests/test_testing_completion_contract.py
backend/tests/test_testing_completion_concurrency.py
backend/tests/test_testing_completion_migration.py
backend/tests/test_nmap_dispatch_authorization.py
backend/tests/test_nmap_plan_revalidation.py
backend/tests/test_nmap_adapter_v2.py
backend/tests/test_execution_persistence.py
backend/tests/test_disposable_postgres.py
```

Result: **465 passed, 9 skipped, 0 failed**. After adding two explicit tests, the
same fresh-cluster harness ran the following node IDs: **2 passed, 0 failed**:

```
backend/tests/test_nikto_workflow.py::test_recommended_details_receipt_and_output_are_assessment_isolated
backend/tests/test_nikto_workflow.py::test_scope_loss_during_execution_is_observed_and_never_reported_complete
```

Total distinct passing backend tests: **467**. All nine skips are the explicit
kernel-containment parameter cases, not hidden application regressions. Warnings:
Starlette/httpx deprecation, pytest collection of an imported mapped event class,
and the harness platformdirs runtime-directory fallback. No assertions were
removed: historical migration projections/head assertions and obsolete adapter
monkeypatches were updated; the restricted Nmap role received the new required
queue SELECT while retaining password/DDL/destructive privilege denials.

Frontend: `npm test -- --run` — **315 passed**, 16 files, no failures;
`npm run lint` — passed; `npm run build` — TypeScript and production Vite build
passed. npm warned about the inherited `http-proxy` environment setting; Vitest
printed a jsdom performance suggestion. Neither was a test failure.

`.venv/bin/python -m compileall -q backend/app backend/migrations backend/tests`
and `git diff --check` passed. Migration tests cover current metadata parity,
upgrade/empty downgrade, nonempty downgrade refusal, immutable history, rollback
and restricted worker privileges. Existing migration 0026 and disabled profile
version 1 were left unchanged. PostgreSQL 18.4, actual Nikto, real Linux
containment and browser visual acceptance are **not** reported as passed.

The Codex harness is external to the repository. On Kali, use the isolated-cluster
procedure above, then run `python -m pytest -q` with the same paths to reproduce
the broad suite; no operational URL or migration command belongs in that test
environment.
