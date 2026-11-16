# Phase 2: restricted execution orchestration

Baseline: `f4b668c5f2f58edf02d1c91e96b50aedbe60df6a`.
This release adds a separately operated worker, not an application-startup hook.
No real scan was run during implementation. Operational `uptip` is untouched.

## Trust and invocation contracts

The reviewed release owns `uptip-ipv4-discovery-dispatch` version 1. Its digest
and decision are recorded with each claim. This is independent of the original
`schedule_only` Start consent, which is verified and never rewritten. Neither a
queue row nor a configured tool alone grants dispatch permission.

Network Discovery v2 is exactly `-sn -n -oX -` followed by one canonical IPv4
address. No analyst argv, hostname, subnet, scripts, service or port scans are
accepted. Nmap v1 remains exactly `-sn`: its definition and existing queue
snapshots are retained. The worker records `v1_output_contract_not_dispatchable`
and blocks these requests; it never upgrades or requeues them as v2.

The baseline catalog chooses the highest compatible version per stable key.
Subnet preparation remains v1 and cannot dispatch. New IPv4 scheduling uses
scheduling policy version 2 and Network Discovery version 2. Existing Draft
assessments with stale baseline evaluations require normal reconciliation and a
fresh review. Existing Testing assessments must not be restarted or silently
given additional requests.

Before claim, immediately before launch, periodically while running, and before
finalization, the worker verifies current creator status/role, Testing lifecycle,
scope classification and digest, target revision, immutable Start digest and
activity binding, baseline fingerprint, tool revision and enabled capability,
restricted plan, release policy integrity and exclusive unexpired ownership.
Scope changes, disabled tools, revocation, cancellation or unverifiable state
stop execution conservatively. An expired analyst login session alone is not
revocation of an explicitly confirmed asynchronous assessment; active creator
account/role and password-change restrictions remain mandatory.

## Minimum-privilege Nmap integration

Nmap is installed separately by the Kali operator. UPTIP does not install it.
The worker requires a dedicated non-root, capability-free Linux account. The
executable must have a canonical absolute path, root-owned non-writable parent
directories, root ownership, no setuid/setgid bits or file capabilities, an exact
administrator-pinned SHA-256, and an exact configured stable `7.xx` version.
SVN/development version strings fail closed. Version verification uses only
`--version`, never a target. Supported behavior must also be checked against the
installed Kali package before an approved local smoke test.

Nmap documents that unprivileged host discovery uses TCP connect probes to
ports 80 and 443: https://nmap.org/book/man-host-discovery.html . These are host
discovery probes, not enumeration of port/service results. Root/raw-packet and
privilege-bearing executors are rejected. The adapter sanitizes the environment,
forces unprivileged mode, sets Linux `no_new_privs`, pins the open executable
descriptor, supplies an argument array with `shell=False`, disables stdin and
creates a dedicated process group. It never uses sudo or adds invocation flags.

Default maximum duration is 600 seconds, total stdout plus stderr is 10 MiB,
and safety verification interval is 5 seconds. Smaller limits are supported;
larger ones are rejected. Database connections/queries have bounded timeouts;
verification failure stops the process rather than extending authorization.
Polling intervals are not a guarantee of instantaneous revocation over a failed
database connection. A single worker and at most one active/uncertain attempt
per database is deliberately conservative for this release.

## Transactions, ownership and recovery

Claim order: worker claim advisory transaction lock, creator SHARE lock,
assessment UPDATE lock, global source SHARE locks, request lock, attempt lock,
then processing locks. `lock_execution_dispatch_sources(uuid)` provides narrowly
scoped privileged locking without granting the worker UPDATE on users or scope.
Tool-table SHARE locks block both updates and insertions during launch checks.
The launch transaction holds the locks only across final validation, Popen and
recording process identity; no transaction spans the scan.

Claims, events and lifecycle writes commit together. The partial unique active
attempt index remains authoritative. Lease expiry never permits another claim.
Boot ID, PID and process start ticks are recorded; migration 0019 prevents their
replacement. A worker crash between process launch and database commit is not
an atomic OS/database operation: the durable earlier claim remains active and
requires recovery, preventing relaunch. Startup marks expired claims/running
attempts RecoveryRequired. Any uncertain active attempt blocks further launches.

Termination requires reaping the owned process and verifying its process group
is gone. Unconfirmed termination stays RecoveryRequired, never Completed. This
release deliberately has no automatic recovery reset or PID-based adoption.
Operators must investigate uncertain processes; do not manually clear claims or
rewrite historical records to resume work. An audited recovery action can be
designed separately once its operational requirements are approved.

## Evidence, processing and APIs

Original stdout and stderr are retained, with SHA-256 and partial indicators.
Up to 1 MiB is inline; larger output uses a private worker-owned directory and
opaque `evidence/<uuid>` keys. Files use exclusive creation, 0600 permissions
and file/directory fsync. Do not delete unreferenced files automatically after
uncertain transactions. A killed worker can lose output still held in memory;
such attempts remain RecoveryRequired and are never called complete.

The parser accepts only bounded Nmap host-discovery XML. It permits Nmap's
literal inert `<!DOCTYPE nmaprun>` declaration, rejects external/internal DTDs,
entities and UTF-16/NUL input, limits nodes/depth while parsing, rejects port,
script, OS and trace results, and verifies exactly one authorized IPv4 target
and consistent run totals. It emits only host up/down observations. Original
evidence is committed with its processing outcome. Processing retries use
versioned runs and observation deduplication, without overwriting prior results.
Scanner success and processing success are separate. Both are required for
overall Completed, including the unchanged Phase 1 database completion guard.

The existing protected Testing routes remain. Overview lifecycle, counts and
discovery data use one SQL snapshot. Execution details add attempts, scanner
outcomes, evidence metadata, processing outcomes, observations and event history.
They expose no stdout, stderr, evidence paths, process identity or secrets.
The existing `execution_authorized: false` is retained: this read response is not
a reusable permission to dispatch. No percent progress is invented. No React
Testing page or new frontend route is included. Analyst cancellation UI/API is
not added; the worker observes persisted cancellation and shutdown signals.

## Migration and deployment: separate approval required

0018 is unchanged. Additive 0019 follows it, introduces the locking function and
process-identity trigger, and grants the existing application role read-only
access to execution persistence for protected Testing APIs. It creates no worker
role, changes no existing records, and performs no scanner checks. Downgrade
refuses once process identities exist; otherwise it removes only its additions.

Do not migrate operational `uptip` as part of importing this bundle. First back
up and verify the environment under separate approval, then test 0017 -> 0018 ->
0019 on a disposable PostgreSQL 18 database created with `TEMPLATE template0`.
Do not alter Kali's template collation or previously applied migrations.

A DBA separately creates a non-owner `uptip_worker` role with no superuser,
CREATEDB, CREATEROLE, BYPASSRLS, schema CREATE, database CREATE, owner-role
membership, DELETE, TRUNCATE, TRIGGER or DDL privileges. Grant USAGE on public,
CONNECT, and only:

```sql
GRANT SELECT(id,status,role,password_change_required) ON users TO uptip_worker;
GRANT SELECT ON assessments, assessment_targets, scope_entries,
 assessment_start_authorizations, baseline_assignments, baseline_evaluations,
 baseline_tool_states, baseline_execution_requests TO uptip_worker;
GRANT SELECT,INSERT ON execution_attempts,scanner_evidence,
 result_processing_outcomes,security_observations,execution_events TO uptip_worker;
GRANT UPDATE ON execution_attempts,result_processing_outcomes TO uptip_worker;
GRANT UPDATE(status,updated_at) ON baseline_execution_requests TO uptip_worker;
GRANT EXECUTE ON FUNCTION public.lock_execution_dispatch_sources(uuid) TO uptip_worker;
```

Do not grant password-hash or session-cookie access. Do not run the worker as
the migration owner or ordinary application role. Startup rejects privileged
database roles. Keep connection credentials in secure service configuration,
not Git, argv or a shared repository environment file.

Create a private evidence directory owned by the OS worker account (0700).
Use a service with User=uptip-worker, NoNewPrivileges=yes, empty capability sets,
ProtectSystem=strict, ProtectHome=yes and write access only to the evidence
directory. A service shutdown should terminate the whole service control group.
Set `UPTIP_DATABASE_URL` to the dedicated worker identity using secure service
configuration. Use the existing trusted tool-state maintenance process; never
mark an unavailable integration enabled just to pass readiness.

The shared Settings loader also requires UPTIP_RATE_KEY. Supply a separate
worker-specific random value through service configuration; the worker neither
needs nor uses the application's login/session or Start-review signing keys.

After separate local scan approval, a trusted operator can run:

```bash
python -m app.execution_worker --executable /usr/bin/nmap \
  --sha256 REPLACE_WITH_VERIFIED_INSTALLED_BINARY_SHA256 \
  --version REPLACE_WITH_EXACT_SUPPORTED_7_XX_VERSION \
  --evidence-directory /var/lib/uptip/evidence --once --enable-dispatch
```

The opt-in is not authorization: every request still passes dispatch checks.
Do not use this command for the first time against an existing real assessment.
Use a newly authorized controlled local IPv4 target and a new reviewed v2 Start.
Confirm Queued -> Running -> Completed/Failed with persisted attempts, original
evidence, processing and observations through the protected APIs. No public or
third-party targets are authorized by this document.

## Verification recorded for this transfer

The final selected regression run passed **282 tests**, with **3 deselected**
legacy fixture bodies and one existing Starlette/httpx deprecation warning.
Those three bodies are password-change concurrency, duplicate assessment creation
and duplicate target creation; their original assertions also run through the
committed disposable-session wrappers in test_execution_persistence.py and
test_scheduling_start.py. Direct use of their old shared-transaction fixtures
produced challenge-expiry/permission errors, not positive execution results.

The workspace provides Python 3.12.14 and PostgreSQL 16.2. PostgreSQL 18.4 and
Python 3.13.14 verification remains required on Kali; it is not claimed here.
Disposable upgrade through 0019, empty 0019 downgrade/reapply, process-identity
immutability and refusal to downgrade recorded identity history are covered.
No live Nmap smoke test or operating-system service deployment was performed.
No frontend files changed, so frontend tests/build were not required.

Set UPTIP_TEST_DATABASE_URL to the marked dedicated disposable database
`uptip_test_readiness_fix`, and set UPTIP_DATABASE_URL and
UPTIP_MIGRATION_DATABASE_URL to separate runtime/owner identities for that same
disposable environment. Never inherit operational database destinations. The
pytest guard checks the exact database name, loopback host and database comment
`UPTIP disposable integration test database`. Create disposable databases using
TEMPLATE template0. Migrate only that verified disposable environment to head.

From the repository root, focused verification is:

```bash
python -m pytest backend/tests/test_execution_orchestration.py \
  backend/tests/test_nmap_adapter_v2.py backend/tests/test_execution_persistence.py \
  backend/tests/test_scheduling_start.py -q
python -m compileall -q backend/app backend/migrations
git diff --check
```

The broader verified run additionally included test_auth.py, test_security.py,
test_password_change.py, test_assessments.py, test_scope.py, test_targets.py,
test_execution_policy.py, test_nmap_execution_binding.py,
test_nmap_dispatch_authorization.py, test_nmap_plan_revalidation.py,
test_system_authorization_verifier.py and test_system_authorization_issuer.py.
For that run only, the pytest expression was:

```text
not test_concurrent_changes_accept_only_one and not test_concurrent_same_key_creates_one_draft_and_event and not test_concurrent_normalized_duplicates_create_one_target
```

The separately configured authorization_isolated fixtures and entire historical
migration suite were not represented as a full-suite pass. They require their
own guarded disposable databases/revisions and must never be redirected to uptip.
