# Evidence-based recommendation planner v2

Base: `fix/phase3-testing-integration` at `d23f28191a4e40aaf96f9a4bc8b40a64b8c49e44`.

## Findings and implemented boundary

Nmap is the only operational tool. Its approved v2 profile uses exactly
`-sn -n -oX -` for one canonical scoped IPv4 address. Its parser emits only
`host_discovery`, and the database trigger explicitly forbids that profile from
claiming ports, services or vulnerabilities. None of those controls are changed.
The ZAP baseline catalog entry is preparation-only, not an integration or adapter.
Nikto has no operational registration.

Consequently, current real host-only Nmap results correctly produce **no suitable
follow-up test**. They do not justify HTTP, Nikto, ZAP, application, version or
vulnerability claims. This is intentional and tested through the actual API.
The former new generic host-review placeholder is no longer generated.

The pure deterministic planner can consume validated service/application facts
from future trusted normalization pipelines. No such facts are fabricated or
persisted by the operational Nmap code in this change. Upcoming tool integration
must supply the actual producer and its secure execution/normalization contract.

## Planning rules and capability definitions

Release-owned definitions in `recommendation_capabilities.py` are immutable,
versioned and hashed. They are **planning objectives**, not executable profiles.

| Evidence | Proposed objective | Tool | Current availability |
| --- | --- | --- | --- |
| Complete open TCP service explicitly identified as http/https, with canonical IPv4 and explicit port | HTTP Server Assessment | Nikto | Pending integration; no executable profile |
| Explicitly verified web application with HTTP(S) URL, canonical matching IPv4 and matching explicit port | Web Application Assessment | OWASP ZAP | Pending integration; no executable profile |
| Host up/down, bare open port (including 80/443), unknown/SSH/SMTP service, missing or malformed facts | No suitable recommendation | None | No invented capability |

A server-service fact does not prove an application exists. A web-application fact
is a different typed assertion. URLs with credentials, fragments, mismatched
hosts/ports or unsupported schemes are rejected. No DNS or network calls occur.
No service version is invented. Partial facts and invalid ports are ignored.
Different evidenced objectives may yield multiple suggestions; HTTP is not a
hardcoded universal Nikto mapping.

IDs hash planner version, target identity, normalized facts and the capability's
version/digest. Duplicate evidence of an unchanged condition does not create a
new Pending item. For a service/endpoint, latest complete observation context is
selected deterministically; immutable old observations remain stored. Changed
versions/facts/definitions can produce a new identity. The pure planner supports
an internal trusted completed-objective exclusion set; no client controls it.
There are currently no implemented executable follow-up profiles to exclude.

Before future integrations advertise a supported (rather than pending) objective,
register a real compatible configured profile, adapter and validated producer,
then implement independent recommendation dispatch authorization. Merely setting
a tool-state row or `integrated` flag cannot make a suggestion executable. This
release intentionally offers no supported follow-up execution path.

## Provenance, reads and decisions

Recommendations and completion share classification. Real API sources require
matching assessment/evidence/processing/request provenance, Completed requests,
Succeeded processing and nonpartial evidence. A processing failure or active run
never becomes a verified recommendation source. Original evidence retrieval and
integrity mechanisms remain separate and unchanged.

The existing Recommendations API retains IDs and count/decision_counts, and adds
planner_version, context_digest, three explanation paragraphs, proposed_test
(name/tool/description/version/definition_digest/profile_id),
tool_integration_status, execution_unavailability_reason and review_outcome.
Source test enrichment includes its actual execution ID, tool, name and status.
The original reason/suggested_test/suggested_tool fields remain available.

T-04C retains its sections, drawer and footer styling. It displays discovery,
unanswered security question and objective/tool rationale as three paragraphs.
Proposed test information stays visible while integration is pending. Accept,
Reject and Choose Alternative never start a scan; unavailable alternatives remain
disabled. The frontend waits for authenticated authoritative readback before
showing a saved outcome and does not automatically retry an uncertain POST.

The existing CSRF/Origin/session/assessment-protected decision endpoint accepts
optional `review_outcome: Accepted | Rejected` only with `decision: Reviewed`.
Reviewed/Deferred and completion semantics remain intact. Acceptance/rejection
records analyst review, not organizational approval or execution permission.
Repeated identical outcomes are idempotent under the assessment lock. Outcome
changes append immutable events with monotonic per-recommendation revision,
actor, context digest and the reviewed snapshot including source IDs. Reads use
revision order, not wall-clock ordering. Completion digests bind these events;
changing an outcome invalidates a previously reviewed completion digest even
when counters stay equal. Existing historical receipts are never rewritten.

An existing Deferred legacy host-review ID is carried as historical review work,
not newly generated advice. It remains blocking until explicitly reviewed via
Testing Completion. Upgrading the planner must not silently clear deferrals.
Unchanged rejected current IDs remain visibly Rejected rather than becoming new
Pending suggestions. Materially new facts may warrant a distinct review.

## Migration and security

`0023_recommendation_reviews.py` follows 0022, adding only
`recommendation_review_events`. Foreign keys, digest/snapshot checks, revision
uniqueness/index, immutable UPDATE/DELETE/TRUNCATE triggers, source binding and
active-Testing INSERT validation protect history. Runtime receives SELECT/INSERT
only; runtime must not own the table or have DDL/superuser privileges. Downgrade
refuses when review history exists. Empty downgrade/upgrade is safe. Previous
migrations and operational database records are untouched.

Apply 0023 on Kali only after separate environment verification, a verified backup
and migration approval. Importing the Git bundle does not migrate anything.
Recommendations/completion need 0023 before using this application version.

## Test evidence and limitations

Planner unit tests use explicitly synthetic typed facts. Completion/decision
contract fixtures mock the planner output, not scanner output, so they can test
review persistence without making Nmap claim services. Dedicated API tests verify
that actual fake-adapter Nmap normalization remains host-only and generates no
web suggestions. Security tests retain the operational observation guard.

Disposable PostgreSQL tests cover provenance, role/CSRF/isolation, idempotent
reviews, immutable history, downgrade refusal, digest changes and existing worker,
Start and completion regressions. No scanner is installed or launched. Frontend
tests cover dynamic T-04C content, decisions, uncertain writes and disabled actions.

For isolated PostgreSQL 18 setup and full Phase 3 regression commands see
`phase3-integration.md`; add `backend/tests/test_intelligent_planner.py` to pytest.
Run `npm test -- --run`, `npx tsc -b --pretty false`, `npm run lint`,
`npm run build`, Python compilation and `git diff --check`. No operational
migration, PostgreSQL 18.4 or actual-browser/pixel-perfect acceptance is claimed.

## Verified build results

- Python 3.12.14, disposable PostgreSQL 16.2: 356 backend tests passed, zero
  failures/skips. The selection includes authentication, Start, persistence,
  worker/dispatch safety, recommendations, completion, concurrency and migrations.
- Frontend: 233 tests passed; TypeScript, ESLint and production build passed.
- Python compilation and Git diff validation passed.
- Existing warnings: Starlette/httpx deprecation, pytest ORM-class collection,
  runtime-directory fallback and npm environment `http-proxy` configuration.
- No operational database migration or real scanner was run. PostgreSQL 18.4 and
  actual Kali browser acceptance remain pending. Figma frame 429:257 was located;
  the existing drawer structure/styles were reused, not pixel-perfect certified.
