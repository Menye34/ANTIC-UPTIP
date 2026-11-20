# Opt-in Nmap TCP Service Discovery v1

Service discovery is a separate capability, never automatically added to Start
Assessment or the baseline catalog. Host discovery v1/v2 and immutable historical
Start records retain their existing meaning. Nikto and OWASP ZAP remain pending,
non-executable integrations. This feature does not run recommended tests.

## Fixed release profile

`service-discovery` version 1, tool Nmap, activity Service Discovery; capability
`tcp-service-discovery`. Release authority: `uptip-tcp-service-discovery` version 1.
Its canonical content digest is recorded with explicit consent and worker events.
The only invocation is:

```
nmap -sT -sV --version-light -Pn -n --max-retries 1 --max-parallelism 4 --max-rate 20 --host-timeout 300s -oX - -p <sorted-explicit-ports> <canonical-IPv4>
```

Exactly one currently in-scope canonical IPv4; 1–16 unique TCP ports, each
1–65535. The creator explicitly authorizes those ports. No default ports, CIDRs,
hostnames, arbitrary flags, `--script`, `--script-args`, OS detection, UDP scans,
or alternate target expansion are accepted. `-sT` uses unprivileged TCP connects;
`-Pn` avoids adding a discovery-probe port set; `-n` disables DNS. `-sV` performs
active service detection, including standard built-in NSE version detection;
that behavior is explicitly accepted for this profile. It is not a no-scripts
profile and does not guarantee probes are passive. Nmap's standard version
intensity-light behavior (including its version-port probe preferences) applies.
No scripts are chosen by users and script output is not promoted to observations.

The existing trusted, administrator-installed standard Nmap executable is used.
The worker must remain non-root, capability-free, with pinned executable path,
SHA-256 and version, sanitized environment, no shell, no_new_privs, supervised
process group, bounded output, cancellation and runtime revalidation. Operators
must protect the installed Nmap data/probe/script files with normal package and
root-owned filesystem permissions. No Nmap installation or scanner execution
is performed by migrations or tests. Never run a worker against an operational
target merely to validate installation.

Limits: one live attempt globally, 16 ports, connect parallelism 4, port-scan-rate
cap 20 (not a global NSE/service-probe rate guarantee), one retry, Nmap host timeout 300 seconds, outer worker timeout at most
600 seconds, combined output at most 10 MiB, runtime authorization checks at
most five seconds apart. These bound scanning work and output; the adapter does
not introduce a new OS memory quota. Process/container resource limits remain
an operator responsibility.

## Explicit scheduling and consent

After normal Start has put the assessment in Testing, an authenticated active
Security Analyst **creator** may explicitly confirm service discovery through:

`POST /api/v1/assessments/{assessment_id}/testing/service-discovery`

Same-origin authenticated session, trusted Origin, X-CSRF-Token, UUID
Idempotency-Key, JSON body (no additional fields):

```json
{"target_id":"<existing-target-uuid>","ports":[80,443],"confirmed":true}
```

The body is an explicit authorization of exactly these TCP port boundaries;
assessment IP scope alone does not grant port-scanning consent. Obtain actual
permission for the selected ports before calling this action. No guessed ports
or synthetic approval/evidence is generated. This opt-in API is separate from
Start; the current frontend displays its executions and observations but does
not add a new scheduling form or redesign Testing.

A valid original Start snapshot must include that exact target as eligible,
with unchanged scope and target revisions. A current resolved host baseline,
current trusted Nmap tool state, both `ipv4-discovery` and
`tcp-service-discovery` capabilities, and current profile integrity are required.
Operator-attested capabilities are not inferred from the profile name. Use the
existing internal `app.baseline_maintenance tool-state` command (not an analyst
approval UI) after independently verifying the configured integration; include
both capabilities and reconcile current baselines. A capability change after
Start is allowed for fresh service consent if the current baseline has been
reconciled. Historical Start snapshots are never rewritten or treated as service
consent. Later changes invalidate the newly captured consent.

201 returns an immutable scheduling receipt: execution_id, assessment_id,
target_id, consent_digest, expires_at (UTC), original status Queued and
execution_authorized=false. Exact idempotent replay returns 200 and the same
receipt, **not** a claim of current execution state. Read Testing APIs for current
state. Conflicting key/body or another service request for the same Start/target
returns 409. The existing queue uniqueness constraint prevents duplicate work.
There is no automatic retry or reactivation of expired/revoked/failed work.

Consent expires one hour after confirmation. Dispatch independently verifies
release policy, integrity, explicit consent, expiry, revocation, current creator,
Testing lifecycle, exact target/scope, reconciled baseline and tool revision,
plan/ports, and exclusive worker ownership. Existing request/attempt locks and
launch/runtime/final safety checks are reused. Authorization loss stops work;
unverified termination remains RecoveryRequired, never automatically retried.

`POST /api/v1/assessments/{id}/testing/service-discovery/{execution_id}/revoke`
requires the same creator, session, Origin and CSRF controls. It appends immutable
revocation and audit history under the assessment lock. A running worker sees
revocation on its next runtime check. It does not falsely claim instant process
termination. Assigned analysts retain read access but cannot grant/revoke consent.

## Schema and deployment

Additive migration `0024_service_discovery_consent` follows 0023. Separate
append-only consent and revocation records are needed because the original Start
receipt is immutable and does not authorize service discovery ports. Composite
FKs bind consent to the existing assessment/target/request; actor FK, idempotency
uniqueness and existing queue uniqueness apply. Consent and queue/event writes
commit together. INSERT triggers coordinate creator/assessment locking with
workers and completion; UPDATE/DELETE/TRUNCATE triggers reject history changes.
Runtime receives SELECT/INSERT only. Workers need SELECT on these two new tables
in addition to their existing least-privilege grants; no DDL, owner membership,
UPDATE, DELETE or TRUNCATE grants. Downgrade refuses if consent history exists;
empty-table rollback is supported. Migration history through 0023 is unchanged.

Do not apply to Kali `uptip` without backup, environment verification and explicit
operator approval. This implementation tests only marked disposable databases.

## Evidence, processing and recommendation contracts

Original bounded XML and stderr persist unchanged with SHA-256 and existing
assessment/target/request/attempt/evidence provenance. Parser rejects DTD/entity
subsets, malformed or oversized/deep XML, unsuccessful/incomplete output, wrong
addresses, non-TCP/unconsented/duplicate ports and ambiguous service elements.
Partial evidence never produces trusted service observations. Successful scans
without qualifying services can finish with zero observations.

Only explicitly open TCP services with `method=probed`, confidence at least 7,
and bounded non-unknown service names yield `service_discovery`. Nmap's `http` with explicit
`tunnel=ssl` maps to `https`. Port numbers and `method=table` labels never establish
HTTP/HTTPS. Closed, filtered and unknown services produce no service facts. Explicit non-HTTP
services (for example SSH) are retained but do not qualify for HTTP recommendations. Optional bounded service version is retained. No web_application fact or
vulnerability is inferred. NSE output remains original evidence only.

Processor `nmap-service-discovery` version 1 reuses existing processing history,
terminal outcomes and evidence-key deduplication. Successful reprocessing is
idempotent. The unchanged planner produces evidence-grounded **HTTP Server
Assessment — Nikto** recommendations, with stable identity, source evidence,
version/capability snapshots, persisted decisions and deduplication. Nikto stays
pending_integration; review acceptance never grants execution. Host-only evidence
still yields no new recommendation; ZAP requires verified web_application facts.

Existing protected Testing overview/executions/details/recommendation endpoints
and evidence authorization are reused. The frontend shows the service profile,
current execution status and address/port/transport/service/version facts using
escaped React text. It does not fabricate web applications, scan results or counts.

## Validation and Kali acceptance

Automated tests use synthetic XML, fake adapters and harmless synthetic subprocesses,
never real Nmap. See `backend/tests/test_service_discovery.py` for consent, scope,
ports, integrity, expiry/revocation, worker ownership, partial/error/timeout,
provenance, idempotence, recommendations and migration checks. Existing host and
planner regression suites remain applicable.

Before a separately authorized isolated scanner acceptance test on Kali:
1. Review and back up the development environment; approve migration 0024.
2. Validate upgrade/downgrade on a disposable PostgreSQL 18 database using the
   existing marked-database fixtures. Do not point pytest at operational `uptip`.
3. Review least-privilege runtime/worker grants and administrator-owned Nmap files.
4. Attest both trusted Nmap capabilities using existing maintenance tooling.
5. Start an assessment with genuinely authorized isolated IPv4/port boundaries.
6. Explicitly schedule service discovery using the protected API above.
7. Inspect persisted Queued requests before enabling the separately configured
   worker. Live scanner execution requires explicit test-target authorization.
8. Verify original XML, processing/observation provenance and pending Nikto
   recommendation through protected Testing APIs and the browser.

PostgreSQL 18 and actual Kali/browser acceptance must be reported separately from
local automated validation; no live scan is required or claimed by these tests.

### Implementation verification record

Validated locally on Python 3.12.14 / disposable PostgreSQL 16.2. Final backend
selection: **387 passed, 0 failed, 0 skipped** (including 41 service-specific
cases). Frontend: **234 passed**. TypeScript (build's `tsc -b`), ESLint, Vite
production build, Python compilation and `git diff --check` passed.

The backend selection, after initializing and migrating ONLY the positively
marked disposable database with the existing test harness, was:

```bash
.venv/bin/python -m pytest -q \
  backend/tests/test_service_discovery.py \
  backend/tests/test_execution_orchestration.py \
  backend/tests/test_nmap_adapter_v2.py \
  backend/tests/test_nmap_dispatch_authorization.py \
  backend/tests/test_nmap_execution_binding.py \
  backend/tests/test_nmap_plan_revalidation.py \
  backend/tests/test_execution_persistence.py \
  backend/tests/test_scheduling_start.py \
  backend/tests/test_intelligent_planner.py \
  backend/tests/test_recommendation_planner.py \
  backend/tests/test_recommendation_eligibility.py \
  backend/tests/test_recommendation_authorization_review.py \
  backend/tests/test_recommendation_authorization_schema.py \
  backend/tests/test_phase3_integration.py \
  backend/tests/test_testing_completion.py \
  backend/tests/test_testing_completion_contract.py \
  backend/tests/test_testing_completion_concurrency.py \
  backend/tests/test_testing_completion_migration.py \
  backend/tests/test_auth.py backend/tests/test_security.py \
  backend/tests/test_assessment_start.py backend/tests/test_assessment_readiness.py
npm test -- --run
npm run lint
npm run build
.venv/bin/python -m compileall -q backend/app backend/tests
git diff --check
```

Non-failing environment warnings: Starlette's httpx deprecation, pytest's
collection warning for an imported ORM `TestingCompletionEvent`, pgserver's
runtime-directory fallback, and npm's pre-existing http-proxy configuration
warning. No warning was suppressed to make validation pass. No actual scanner,
Kali database, production database or browser acceptance test was run.
