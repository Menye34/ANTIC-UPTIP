# Service Discovery dispatch diagnosis and deployment

## Finding and evidence boundary

Investigation baseline: `a568c646ca8ee2307909fa5352f99bd5a20771f0` on
`feat/expanded-web-service-ports`. The Kali worker started at 03:19:57 WAT
on 2026-11-21; policy v3 was imported at 04:07:05 WAT; the request was blocked
at 04:49:39 WAT. A long-running Python worker does not reload previously
imported modules after a Git checkout. Reproduction with the previous v2-only
validator produces `start_service_scope_binding_invalid` for a valid v3
preparation; the current validator accepts those same five binding inputs.

This strongly supports stale worker code, but does not prove which modules that
historical process had loaded. The old event has no worker-policy metadata.
No mutation, race, or database inconsistency has been demonstrated. Passing five
checks in a later diagnostic is not proof of complete dispatch authorization.
No further runtime read is necessary to correct the confirmed reporting and
diagnostic defects. Definitive historical attribution requires retained process
or deployment logs; do not alter the original event to supply missing metadata.

## Behavior and compatibility

The five previously combined binding checks now have separate denial codes:

| Code | Failed condition |
| --- | --- |
| `service_scheduling_policy_version_unsupported` | Reviewed policy version is not supported by this worker |
| `start_service_reviewed_preparation_invalid` | Preparation shape, fingerprint, policy definition or reconstructed plan is invalid |
| `start_service_activity_match_invalid` | Missing or duplicate matching authorized activity |
| `start_service_authorization_binding_invalid` | Authorized activity differs from reviewed preparation |
| `start_service_plan_binding_invalid` | Consent execution plan differs from reviewed plan |
| `start_service_scope_ports_changed` | Current permitted port set differs from reviewed plan |

Historical `start_service_scope_binding_invalid` remains valid historical data;
its specific failed predicate cannot be recovered from that code alone. No old
events, receipts, policies, consents or Blocked requests are rewritten. Versions
1, 2 and 3 remain supported with their original definitions and digests. New
Start reviews still use v3 (80, 443, 3000, 5000, 8000, 8080, 8443, 8888), narrowed
by any existing explicit port boundary. This does not change scanner arguments.
An unsupported policy fails closed; it is not silently converted or approved.

Worker startup emits one `uptip_worker_started` JSON line with a diagnostic
format/version identifier and identities/digests of the loaded policies. New
worker events include the same safe metadata in `details.worker`. No passwords,
database URLs, executable paths, tokens, environment variables, signatures or
target data are included in that metadata. Policy-diagnostic failure is marked
unavailable and must not suppress an authorization-denial audit event. These
identities are diagnostics, not a new authorization mechanism or a Git SHA.

Execution Details retains its coherent single-statement read. `status` is the
actual persisted request lifecycle. `dispatch_status` is the latest persisted
dispatch milestone (`execution_claimed`, `scanner_started`, `dispatch_blocked`),
or `not_recorded`; it no longer hardcodes `requires_fresh_authorization`.
`dispatch_history` is that event (`id`, `event`, `reason_code`, `occurred_at`,
`attempt_id`) or null. A Completed request may correctly have a historical
`scanner_started` milestone: this is not a claim it is still Running.
`execution_authorized` remains false in read responses. Historical launch or
claim success is never permission for another execution.

The existing right drawer shows the persisted outcome and reason, with the full
event timeline in its existing Technical Details disclosure. No scheduling or
retry action is added. Existing lazy evidence retrieval, integrity checks, safe
text rendering, authentication, assessment isolation, CSRF, review, scope,
consent expiry/revocation, worker ownership and runtime gates remain intact.
The frontend accepts older responses without the new optional history field,
but validates identity/event/time/reason structure when that field is supplied.

Blocked requests do not produce attempts or observations and are not requeued by
a worker restart. Recommendations still require trustworthy persisted evidence
and successful processing. A manual Nmap command is not imported as evidence.
HTTP identification can support a Nikto proposal; Nikto/ZAP execution remains
unavailable. No recommendation is fabricated for a blocked or host-only request.

## Safe Kali deployment and worker restart

No migration is added or modified. A database already at 0025 needs no upgrade.
Do not downgrade, reset, truncate, change request status, extend consent, or
edit history to repair a blocked execution.

Before changing files, arrange a maintenance window: stop creating new work,
check active attempts and let any scan finish. Use your existing read-only
PostgreSQL administrative connection:

```sql
BEGIN READ ONLY;
SELECT status, count(*) FROM execution_attempts
WHERE status IN ('Claimed', 'Running', 'RecoveryRequired') GROUP BY status;
SELECT status, count(*) FROM baseline_execution_requests
WHERE status IN ('Queued', 'Running') GROUP BY status;
COMMIT;
```

Do not proceed with routine restart if a process is active or its termination is
uncertain. Resolve it through the existing supervised shutdown/recovery procedure;
do not kill it blindly or reset RecoveryRequired. Review queued work too: starting
the service can dispatch eligible requests immediately. Stop an idle worker
**before** installing code to avoid mixing lazily imported modules from releases:

```bash
sudo systemctl stop uptip-execution-worker.service
systemctl show uptip-execution-worker.service -p ActiveState -p SubState -p MainPID
```

Import the verified bundle with the supplied clean-tree/ancestry checks. Restart
the FastAPI backend using its existing service or foreground factory command;
ensure only one backend owns port 8000. Restart/rebuild the frontend by the normal
development procedure. Do not edit or disclose `.env` or `.env.worker`.

Inspect installed code without connecting to PostgreSQL or invoking Nmap:

```bash
cd ~/ANTIC_Project/UPTIP/frontend
source .venv/bin/activate
PYTHONPATH=backend python -m app.execution_worker --diagnostics
```

Expect `worker_version=execution-worker-dispatch-diagnostics-v1`, current service
scheduling version 3, supported versions 1/2/3, and `policy_diagnostics_available`
true. This command proves the installed code, not what an older running process
has loaded. Once queued targets are explicitly authorized and maintenance is
complete, start the configured non-root service with its existing pinned Nmap:

```bash
sudo systemctl start uptip-execution-worker.service
systemctl show uptip-execution-worker.service -p ActiveState -p SubState -p MainPID -p ExecMainStartTimestamp
sudo journalctl -u uptip-execution-worker.service --since '5 minutes ago' --no-pager |
  grep 'uptip_worker_started '
```

Verify the startup diagnostic from that service, rather than relying only on a
fresh shell command. Do not install another Nmap, broaden role privileges, disable
dispatch checks, or modify unit security settings. Review service launch failure
before retrying; repeated restarts cannot repair consent or target mismatches.

## Authorized functional acceptance

Only use a separately authorized, isolated local test target. Do not rerun the
old Blocked execution `288c4b94-9434-469c-9d4b-bbc8377b73e4` or resubmit its Start.
Create a fresh Draft assessment with explicit scope and a current canonical IPv4
target. Verify current baseline/tool state and both Nmap capabilities. Inspect
the normal Start review: v3 service preparation must include only its reviewed,
permitted ports (8080 if not excluded by a narrower explicit boundary). Confirm
once through the existing creator workflow.

Observe durable Queued requests. Network Discovery must complete before Service
Discovery can dispatch. Inspect the protected Execution Details endpoint/drawer:
Queued with no dispatch event is `not_recorded`; a claimed/launched request has
the respective historical milestone. Any block must show its recorded reason.
Queued is not Running; a launch is not successful processing. Verify completion,
nonpartial XML evidence, successful service processing and actual normalized
HTTP/HTTPS facts before expecting recommendations. A closed port, weak/table
service guess, non-HTTP service or failed/partial processing may correctly yield
no recommendation. Confirm Nikto/ZAP controls remain unavailable.

Check the original Blocked request and its original audit event remain unchanged.
Do not use SQL INSERT/UPDATE to fabricate success or force a retry.

## Automated verification

Use only the repository's marked disposable PostgreSQL fixtures, never the
operational database `uptip`. Relevant suites are
`test_service_dispatch_diagnostics.py`, `test_automatic_service_start.py`,
`test_service_discovery.py`, `test_testing_read_projection.py`,
`test_baseline_scheduling.py`, scheduling/scope/dispatch/orchestration/persistence,
planner/recommendation and Testing Completion regression suites. The diagnostic
tests cover individual failures, unsupported worker versions, one persisted
Blocked result without attempts or retries, historical v1/v2/v3 verification,
safe metadata and absence of fabricated recommendations. Existing tests cover
revocation, expiry, scope restrictions, evidence integrity and assessment access.

Frontend commands: `npm test -- --run`, `npm run lint`, `npm run build`.
Run backend pytest against the verified disposable configuration and use
`python -m compileall -q backend/app backend/tests` plus `git diff --check`.
PostgreSQL 18.4 and actual Kali/browser acceptance must be reported separately
from workspace PostgreSQL 16.2 and jsdom checks. No live scanner test is implied.

### Verified results for this correction

- Final backend regression: **402 passed, 0 failed, 0 skipped**, disposable
  PostgreSQL 16.2 and Python 3.12. This includes the new 14 diagnostic/history
  cases, migration metadata/rollback protections, concurrency, scheduling,
  authorization, evidence, planner and Testing Completion tests.
- Full frontend: **303 passed**, 15 files; ESLint and TypeScript/Vite production
  build passed. Python compilation and Git diff validation passed.
- A prior broader run exposed one outdated v2 test expectation after clearing
  a legacy port restriction (401 passed, 1 failed). The test now verifies the
  restricted set before clearing and the exact approved v3 set afterward. No
  production policy was changed to satisfy that test. The full rerun above passed.
- Existing warnings: Starlette/httpx deprecation and pytest attempting to collect
  the imported TestingCompletionEvent model. Test-server setup emitted an
  XDG runtime-directory warning; npm emitted its proxy configuration warning and
  Vitest a jsdom performance advisory. None caused skips or failures.
- Policies 1/2/3 were compared to `a568c64`: exact definitions and digests match.
  Alembic has a single head 0025; migrations and models are unchanged.
- No operational database or real scanner was used. PostgreSQL 18.4 and actual
  Kali browser acceptance remain unverified in this workspace.

After configuring only the existing verified disposable test environment, the
exact pytest selection is:

```bash
: "${UPTIP_TEST_DATABASE_URL:?Configure the marked disposable test database first}"
python -m pytest -q \
  backend/tests/test_service_dispatch_diagnostics.py \
  backend/tests/test_testing_read_projection.py \
  backend/tests/test_automatic_service_start.py \
  backend/tests/test_scoped_service_start.py \
  backend/tests/test_scheduling_start.py \
  backend/tests/test_baseline_scheduling.py \
  backend/tests/test_service_discovery.py \
  backend/tests/test_scope.py \
  backend/tests/test_execution_orchestration.py \
  backend/tests/test_intelligent_planner.py \
  backend/tests/test_recommendation_planner.py \
  backend/tests/test_recommendation_eligibility.py \
  backend/tests/test_recommendation_authorization_review.py \
  backend/tests/test_testing_completion.py \
  backend/tests/test_testing_completion_contract.py \
  backend/tests/test_testing_completion_concurrency.py \
  backend/tests/test_nmap_dispatch_authorization.py \
  backend/tests/test_nmap_plan_revalidation.py \
  backend/tests/test_nmap_adapter_v2.py \
  backend/tests/test_execution_persistence.py \
  backend/tests/test_disposable_postgres.py
```

The Codex run used a fresh temporary local cluster with the fixture-required
database/cluster markers and distinct owner/runtime roles. Do not repoint this
selection or its migration/concurrency fixtures at an operational database.
