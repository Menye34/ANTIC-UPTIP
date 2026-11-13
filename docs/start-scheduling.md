# Restricted Start scheduling

Start schedules work; it does not run a scanner. Application-release policy
`uptip-baseline-scheduling`, version 1, permits only one canonical IPv4 address
per `network-discovery` v1 activity, Nmap `-sn`, capability `ipv4-discovery`,
without scripts, port scanning, or target expansion. Subnets, hostnames, URLs,
other profiles and arbitrary parameters are excluded. Supporting another profile
requires an explicit reviewed policy version, parameter envelope and tests.

The authenticated assessment creator can confirm a Draft assessment with current
explicit authorized scope, at least one in-scope target, a current resolved
baseline evaluation and trusted enabled tool capability. Assignment alone grants
read access, not Start permission. A resolved baseline alone is insufficient:
the server builds and checks the restricted plan and its parameter digest.
Tool state is operator-attested through existing maintenance; never report a tool
as enabled without verifying that attestation. Unknown/disabled/unavailable tool
states and stale baseline evaluations remain blocking conditions.

Readiness is read-only. It returns scheduling eligibility separately from scope
classification and execution permission. `scheduling_preparation` v1 records the
assessment/target, scope digest and revision, target revision, evaluation ID and
fingerprint, tool-state revision, policy identity/version/digest, profile and
parameter digests, restricted plan, verified checks and dependencies. The initial
policy has no cross-activity dependencies; unknown prerequisites are rejected.
These facts are reproducible preparation, not evidence of scanner execution or
independent organizational approval. No deployment approval manifest, policy
activation, external Start evidence or authorization renewal is required for this
restricted scheduling path. Historical execution-policy/evidence infrastructure
remains in place for its independent security boundary.

A dedicated randomly generated `UPTIP_START_REVIEW_KEY` of at least 32 characters
is still required through secure backend configuration. Do not use an example
key in a deployment. Missing/short keys fail closed. Tokens are session-, actor-,
assessment-, mode- and snapshot-bound and expire after ten minutes. Confirmation
requires trusted Origin, CSRF, creator permission and an Idempotency-Key.

Confirmation keeps the existing locking/transaction mechanism: lock actor,
session and assessment, lock mutable global sources, recompute preparation and
snapshot, reject changed inputs, then atomically insert immutable confirmation,
lifecycle audit and Queued requests and transition Draft to Testing. Partial
Start records every exclusion and queues only eligible activities. Exact retries
return the original receipt without additional queues or audit events. New
snapshots use version 3 and purpose `schedule_only`. Stored historical receipts
remain replayable; an old uncommitted review cannot authorize a new plan.

`execution_authorized` remains false. Dispatch of scheduling-only requests is
explicitly denied with `dispatch_safety_checks_pending`, even if an independent
execution policy exists. Runtime scope/parameter enforcement and stop conditions
remain prerequisites for separately approved dispatch work. No scanner worker,
scanner call, network lookup or execution is added here.

## Database and recovery

No model or migration changes are needed; existing JSON snapshots retain the
preparation contract. Migrations 0001–0017 are unchanged. The uncommitted Phase 1
0018 activation migration was removed only after the user confirmed it had never
been applied/distributed to persistent environments. Its seven source files and
tracked patch were archived and verified before removal. No historical
execution-policy or evidence records are deleted.

## Kali verification after code transfer

1. Confirm the reviewed branch and preserve local changes. This change itself
   requires no migration. Check existing schema prerequisites separately; do not
   apply migrations implicitly.
2. Use the existing secure backend environment and review signing key. Start
   backend: `cd backend && uvicorn app.main:create_app --factory --reload`.
   Start frontend from repository root: `npm run dev`.
3. Verify existing trusted tool-state configuration. If baseline inputs changed,
   the existing operator-owned `python -m app.baseline_maintenance reconcile`
   command reconciles them; run it only deliberately against the intended database.
   Do not falsely enable a tool merely to pass readiness.
4. Sign in as the creator, create a dedicated assessment, explicitly authorize an
   appropriate development IPv4 scope and add a canonical single IPv4 target.
   Inspect `GET /api/v1/assessments/{id}/readiness`: policy is system_managed,
   preparation is present and confirmation_possible is true when all checks pass.
   Never share session cookies, CSRF/review tokens or signing keys.
5. Confirm Start through the existing dialog. Verify Testing lifecycle and queued
   count in the receipt; reload and inspect existing `/testing` read APIs. Queued
   is not Running. No scanner should run. The Testing React page is a separate task;
   the current screen does not navigate into a missing page.
6. Check an out-of-scope/unsupported target remains excluded; review expiration,
   changed scope/target/tool inputs and noncreator sessions cannot confirm stale work.

## Regression coverage

`test_scheduling_start.py` exercises the actual default endpoint with no policy
approval/evidence fixtures, plus explicit historical compatibility tests. The
older readiness/Start/scheduling suites use a clearly named test-only legacy
execution-contract fixture to retain execution-policy, evidence and dependency
coverage; they are not evidence that the new default requires such approvals.
Database tests require positively identified disposable PostgreSQL databases.
Never point them at Kali operational data.

The default-path concurrency suite additionally verifies that tool-state updates
and first-time tool insertion wait for Start commit, different idempotency keys
cannot create a second queue, and the Testing overview retains one database
snapshot during concurrent Start. The original creation/target-duplicate race
bodies run on committed isolated sessions. A fresh database migration cycle
preserves Draft data through 0008–0017 and verifies that attempted downgrade with
Testing/history is refused and rolled back. No operational database is used.
