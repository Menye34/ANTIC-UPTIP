# Automatic service discovery in the existing assessment workflow

## Analyst workflow and Figma

The existing Start Assessment confirmation is the only scheduling interaction.
The baseline prepares Network Discovery and restricted Service Discovery for
in-scope canonical IPv4 targets. Service scheduling policy
`uptip-scoped-service-scheduling` **version 2** supplies TCP **80 and 443**.
No manual port input or extra scheduling card is needed. The Start dialog shows
the exact target and prepared ports; normal creator, session, Origin, CSRF,
review expiry, snapshot and idempotency checks remain mandatory.

T-01 remains execution monitoring. It does not expose the supplemental service
scheduling card. Existing T-04C presents evidence-backed planner proposals; opening
it does not execute a tool or persist a review decision. Nikto and OWASP ZAP
remain unavailable for execution. No new layouts, Testing routes or scanner
controls are introduced.

The distinction is intentional:

- Baseline/worker: collect actual authorized scanner evidence.
- Rule-based planner: interpret successful, trustworthy observations.
- Review Recommendation: explain the source test, proposed tool and rationale.

A completed host discovery, a selected port, or an open TCP socket alone is not
proof of HTTP/HTTPS. Only explicit supported scanner observations generate the
Nikto proposal. No verified web-application producer is added in this correction;
ZAP proposals still require genuine `web_application` evidence.

## Safety and versioning

New Start reviews prepare the release-owned fixed port set. An existing nonempty
`scope_entries.tcp_ports` restriction can only narrow this set, never broaden it.
For example an existing [443] restriction yields [443]; [22] excludes automatic
service discovery rather than probing 22 or overriding the saved restriction.
Legacy restrictions remain visible read-only in scope entries and are not
silently cleared by the address form. The historical scope API remains compatible.

Service capability, fresh baseline/tool state, in-scope target, prepared parameters
and dependency checks remain enforced. Missing prerequisites appear in the existing
Start exclusions. A host-only Partial Start does not imply service discovery has
run. Start still atomically records consent, audit and Draft → Testing plus Queued
requests. Pending host discovery keeps its service dependent Queued; a failed
host dependency blocks it. Independent dispatch, ownership, executable pinning,
timeout, cancellation, runtime checks and one-hour consent expiry remain unchanged.
Scheduling consent is never represented as scanner execution authorization.

The web application does not insert worker-owned `execution_events` or invoke
`lock_execution_dispatch_sources`. The existing immutable `AssessmentStartEvent`
and linked `ServiceDiscoveryConsent` provide the scheduling audit, atomically
with the queues. Worker execution events remain worker-owned. This avoids the
permission mismatch concealed by migration-owner-backed test fixtures, without
broadening application privileges. A dedicated test exercises Start with a real
non-owner web role lacking both worker capabilities.

## History and deployment

- Migration **0025 remains unchanged**. No new migration or database rewrite.
- Version 1 policy definitions/digests remain supported for persisted consents.
- New Start reviews use version 2. Previously issued different-version reviews
  require fresh explicit confirmation; persisted receipts retain exact replay.
- Previously started Testing assessments are **not** silently rescheduled.
- Existing explicit-service API and receipt endpoints remain available for old
  clients/history. The current Testing page no longer invokes them.
- Existing requests, port restrictions, consent expiry and audit history remain
  intact. Removing a UI action does not establish that an earlier uncertain
  request failed; inspect persisted execution records if necessary.

For Kali already at 0025, this is a code update, not another migration. Test with
a fresh Draft assessment and an explicitly authorized isolated IPv4 target, with
both Nmap capabilities enabled. Inspect Start review before confirming: eligible
service work should list TCP 80/443 (or a narrower historical boundary). Confirmed
work appears as Queued on Test Activity. A live worker may execute those requests;
real scanner testing requires separately authorized test scope. Automated tests
use fake adapters and disposable PostgreSQL only.

## Workspace verification

- **349 backend tests passed**, no failures or skips, including the real restricted
  application-role test, legacy v1 receipt/consent compatibility, automatic Start
  without port input, fake-worker XML processing, real planner/review persistence,
  no-HTTP empty results, stale reviews, concurrent confirmations and port edits,
  rollback, scope, dispatch, persistence and Testing Completion regressions.
- **276 frontend tests passed**. Scope no longer requests TCP-port input; the
  Testing page has no supplemental scheduling card or scheduling POST; existing
  Start confirmation still displays the prepared target/ports.
- ESLint, TypeScript/production build, Python compilation and `git diff --check`
  passed. Migrations 0001–0025 are unchanged.
- Backend execution used Python 3.12 and disposable PostgreSQL 16.2 only. PostgreSQL
  18.4 and actual Kali browser acceptance have not been performed here.
- Existing warnings: Starlette/httpx deprecation, pytest class-collection warning,
  runtime-directory warning from test PostgreSQL setup, npm proxy configuration
  warning and Vitest environment-performance advisory.
