The current restricted scheduling path is documented in [start-scheduling.md](start-scheduling.md).
New version-3 scheduling snapshots use reproducible preparation facts in place of
external approval/evidence records. The evidence descriptions below also document
historical version-2 snapshots, whose receipts remain replayable.

# Start and baseline scheduling

The implementation is based on ab61c45 on feat/system-managed-authorization.

POST /api/v1/assessments/{id}/start retains the existing creator permission,
session, Origin, CSRF, review-token and idempotency contract. A new accepted
Start atomically records the authorization, Draft to Testing event, and one
Queued execution request per eligible target/profile. Each request retains the
reviewed activity, profile digest/version, parameter digest, safety-evidence
reference, dependencies, tool revision and policy decision. The parent immutable
Start snapshot retains the approved scope and policy provenance.

Queued requests grant no dispatch permission. A worker must resolve the exact
immutable parameter reference, verify it against the stored digest, recheck
authorization, scope, tools, prerequisites and stop conditions, and enforce
runtime safety before any launch. Executor parameter binding and runtime stop
enforcement remain missing capabilities in the current safety verifier.
Configured policies cannot bypass that verifier.

The receipt adds queued_execution_count, queued_execution_ids, testing_url,
excluded_activities and excluded_targets. New receipts use lifecycle_status
Testing. Existing Ready authorizations replay as historical Ready receipts
without scheduling new work. The existing Start frontend accepts Testing and historical Ready receipts, validates
the response identity and queue count, and displays Testing and queued wording.
The future navigation contract is /analyst/assessments/{id}/testing, exported by
assessmentTestingPath. App and AssessmentPage have no Testing view registered,
so successful Start currently stays on the existing Targets screen. It shows
the accepted status without redirecting to a missing page. The backend
testing_url is an API resource, not a frontend URL. Layout and styles are preserved.

GET /api/v1/assessments/{id}/testing returns persisted counters, executions,
authorization/scope details, exclusions, queued activity timestamps and empty
discovery data until real observations exist. Queued is separate from Running.
GET .../testing/executions lists requests. GET .../testing/executions/{id}
returns one request and its authorized input. All reads require an active
Security Analyst with creator or assigned assessment access, enforce assessment
isolation, and use the application's no-store response headers.

Accepted Start and queued creation history are stored transactionally.
Review and rejected-confirmation diagnostics use the uptip.assessment logger
with actor, assessment, and reason codes and no tokens or credentials.
Deployments must retain these application logs to retain rejection history.

Migration 0012 follows 0011, adds composite foreign keys to enforce assessment
isolation, a unique authorization/target/profile constraint, and execution input
immutability triggers. Runtime roles must not own the tables, bypass triggers,
or have DDL/TRUNCATE privileges. The migration preserves existing Ready and
Draft rows and refuses downgrade when Testing assessments or requests exist.
It has been validated on a new disposable PostgreSQL database, including an
independent restricted runtime role. Apply it to development separately after
review and a verified backup. A BEFORE TRUNCATE statement trigger also rejects
truncation of execution history.

Verification uses a newly created disposable PostgreSQL database named
uptip_test_readiness_fix with the exact fixture marker. The test schema is
created from SQLAlchemy metadata. The separate migration test requires
UPTIP_MIGRATION_TEST_URL and UPTIP_MIGRATION_TEST_RUNTIME_URL, pointing to the
same newly created local database uptip_test_migration_0012. Its exact comment
must be "UPTIP disposable migration test database". The runtime username must
be uptip_test_runtime and differ from the migration owner. This test applies
0011 then 0012 only after verifying identity. It exercises upgrade, downgrade,
constraints, triggers, metadata consistency, and restricted-role protections.
The disposable cluster is stopped after the test.

Deployment role checks must grant the application runtime SELECT and INSERT
on baseline_execution_requests so Testing reads and atomic scheduling can work.
Keep UPDATE/DELETE/TRUNCATE, trigger management, and table ownership unavailable
to that role. A future worker requires separately reviewed permissions for
status transitions. Also verify the existing Start table-lock permissions.
This implementation does not grant privileges to any operational role.

Testing overview uses one joined SELECT for lifecycle, authorization and
execution counters. Its concurrency regression commits Start after that SELECT
has executed and confirms the response stays entirely in the earlier snapshot.
The next request sees Testing with the queued request.

The existing Start UI retains its layout and error/exclusion handling. An expiry
timer disables stale reviews, and the event handler independently checks expiry
before submission. An invalid success receipt is treated as an uncertain outcome
and blocks further Start submissions until reload.
