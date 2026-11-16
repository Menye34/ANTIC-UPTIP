# Automatic execution persistence — Phase 1

Baseline: `8055552` on `feat/start-baseline-scheduling`. Migration `0018` follows
`0017`. This is persistence, not a worker or permission to execute scanners.
No operational data, approvals, evidence or events are generated on upgrade.

## Records and relationships

- `execution_attempts`: request/assessment/target binding, attempt number,
  unique claim ID, fixed worker owner, claim/heartbeat/lease timestamps, actual
  start/finish/termination, profile/version, immutable restricted plan and
  parameter digest, timeout, cancellation metadata and recovery reason.
- `scanner_evidence`: immutable original bytes or opaque storage object key,
  SHA-256, byte size, format/tool, collection time and partial indicator.
- `result_processing_outcomes`: evidence-bound numbered/versioned parser runs,
  operation idempotency, Pending/Processing/Succeeded/Failed/Interrupted,
  timestamps, safe error code/diagnostic, observation count and completeness.
  Evidence with no outcome is unprocessed. Latest runs expose processing status;
  scanner success and processing success are separate facts.
- `security_observations`: immutable assessment/target/request/attempt/evidence/
  processing traceability, normalized facts, collection/processing times,
  partial indicator and evidence-scoped deduplication key.
- `execution_events`: append-only request timeline, optional attempt, actor or
  system origin, reason, timestamp, bounded metadata and operation idempotency.
  Scheduling retains its original Start audit; this migration does not backfill
  synthetic queued or execution events.

Composite foreign keys prevent mixing existing identifiers from different
assessments, targets, requests, attempts, evidence or processing runs. No cascade
can erase new execution history. Existing request statuses are unchanged.

## Ownership, recovery and transactions

One partial unique index reserves a request for a Claimed, Running or
RecoveryRequired attempt. Clock-based lease expiry never frees that reservation.
Lease/heartbeat cannot move backwards; ownership, claim and preparation cannot
be reassigned. An interrupted worker requires verified process reconciliation;
a started attempt cannot become terminal without a termination timestamp.
RecoveryRequired cannot resume Running merely by changing its status. A future
worker must serialize request claiming with a request lock, insert the attempt
and audit event atomically, and perform independently approved dispatch checks.
No claim-processing loop or process-supervision mechanism is implemented here.

An attempt is initially accepted only against an existing Queued request with
an exactly matching server-prepared plan and digest. Historical requests lacking
that preparation remain preserved; Phase 1 does not guess parameters or make
those requests executable. Succeeded records scanner outcome, not overall
Completed. Newly completing a request requires scanner success and successful,
complete processing on the latest attempt, without unfinished/failed latest
processing runs. Processing terminal counts must equal persisted observations;
observation insertion locks the processing row and refuses terminal runs.
Processing writes lock the request and refuse Completed requests, serializing
new processing with completion instead of reopening a sealed outcome.
Failed transactions retain no partial database batch. Separate committed partial
batches remain available after interruption. Reprocessing uses new numbered
outcomes, never updates a terminal outcome; observation deduplication reuses
existing evidence-scoped records rather than silently overwriting them.

## Evidence and observations

Inline evidence is bounded to 1 MiB and its size/hash are checked by PostgreSQL.
External evidence is bounded to 64 MiB and uses a relative opaque `evidence/`
object key, not a URL, credential-bearing reference or filesystem path. Phase 2
must implement secure private storage, atomic writes, retention and verification
of external bytes against the stored hash/size. No external-storage adapter is
introduced now. The initial profile accepts Nmap XML and separate stderr text.
Future XML parsing must reject external entities, DTD/entity expansion and
unbounded documents. Treat all scanner output as untrusted.

Nmap `network-discovery` observations can only be host_discovery facts for the
exact prepared IPv4 address, with up/down/unknown status and optional reason/
hostnames. Port, service and vulnerability fields/types are rejected. This
schema does not parse output or certify that submitted facts are genuine; only
a separately reviewed trusted parser may produce them from preserved evidence.
Synthetic XML in tests is explicitly test data, never an assessment result.

No secrets belong in worker IDs, parameters, diagnostics or event metadata.
Future producers must use whitelisted non-sensitive fields, stable error codes
and redacted diagnostics; the schema's byte limits do not themselves redact
secrets. Existing read APIs do not expose these new records. Future evidence and
observation APIs must reuse assessment-level access checks and private retrieval.

## Deployment and rollback

Existing scheduling/authorization immutability triggers remain intact. Evidence,
observations and events reject UPDATE/DELETE; all five new tables reject TRUNCATE.
Terminal attempts and processing outcomes reject further modification. Runtime
roles must not own tables/functions or have superuser, DDL, trigger-disable,
replication-role or destructive privileges. Migration 0018 intentionally grants
no new privileges to ordinary application users. A future worker requires a
separately reviewed least-privilege role and authorization boundary.

Upgrade adds the tables plus a referenced unique request identity; existing
queues and authorized snapshots are preserved byte-for-byte. Empty new tables
can be downgraded while existing queues remain. Once any new history exists,
downgrade refuses rather than deleting it. Applied migrations are not rewritten.
Do not apply to Kali without environment verification, backup and approval.

## Verification

`backend/tests/test_execution_persistence.py` covers persistence, invalid plans,
foreign-key bindings, active uniqueness despite expired leases, recovery,
partial results, immutable history, safe evidence references/hashes/sizes,
processing counts, completion gates, idempotent observations, restricted-role
TRUNCATE privileges, concurrent attempts and a disposable 0017–0018 cycle.
Existing default-path scheduling tests remain separate from legacy policy tests.
Use only explicitly identified disposable PostgreSQL databases. No test command
should point to the operational `uptip` database. No scanner is invoked.

Phase 2 remains responsible for claims/leases, dispatch authorization, worker
recovery, execution, bounded evidence collection/storage, safe parsing and atomic
result/event persistence. Cancellation APIs, Testing frontend, manual tests,
recommendations and Testing Completion are outside Phase 1.

Finalization verification used Python 3.13.5 and disposable PostgreSQL 16.2;
PostgreSQL 18 binaries/container runtime were unavailable, so PostgreSQL 18
acceptance remains pending. The general regression batch excludes twelve legacy
fixture-dependent cases; eight original bodies run through committed isolated
fixtures and four behaviors run through current default-path equivalents.
No legacy assertions or history-protection triggers were weakened to run them.
