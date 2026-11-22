# Operator-controlled Nikto version 2 activation

## Status and trust boundary

Base: `c3d44614c828806a1bed8dab07cd101dbffbaf2d` on
`feat/start-recommended-test`. Kali's nine containment passes and installed
Nikto 2.6.1 were reported by the operator. They do not establish production
worker compatibility or authorize a scan of every port on 192.168.161.131.

The observed service omits all three Nikto binary arguments. That is a worker
configuration problem, separate from the disabled version 1 policy. This change
provides an optional drop-in and version 2 release definition. **Code installation,
migration or startup with default settings does not activate Nikto.** Approved
operator configuration is read at process startup; assessment creation and login
never provision approval. No database/schema change or new worker service is required.

Version 1's definition and digest remain unchanged:
`0697d4df027f87e68d7d9c8447dcbc4e8f4cbfd77d75ee4c19241b12fd474729`.
Version 2 additionally binds Nikto 2.6.1 and the exact existing restricted argv.
It retains one process, 300 seconds, 5 MiB, exact IPv4/TCP containment, no DNS,
no redirects and no proxies. `authority(2)` describes a supported release; it
does not select or approve that release for the environment.

Only a trusted deployment operator may set all three configuration values:

* `UPTIP_NIKTO_POLICY_VERSION=2`
* `UPTIP_NIKTO_POLICY_DIGEST`: the exact version 2 release digest
* `UPTIP_NIKTO_POLICY_APPROVAL_REFERENCE`: an actual approved change/acceptance
  record (3–160 ASCII letters/digits or `-_./:`; no whitespace)

Absent configuration selects disabled v1. Partial, unsupported or mismatched
configuration fails closed. The approval source is the operator-controlled
deployment configuration and its referenced review record, not an analyst API,
a deployment manifest, a signing-key workflow, or an inferred approval from
login. Protect configuration write access and release code ownership accordingly.
This is a deployment permission, never target authorization. It has no automatic
renewal service; queued analyst consent still has its existing one-hour expiry.

API and worker must use identical approval values. Current approval identity is
included in the reviewed digest and immutable consent. Changing/removing it
invalidates reviews/dispatch checks. Restart processes through the existing
deployment procedure to load configuration changes; cached settings do not
watch files. Do not describe config revocation as instantaneous across an old
still-running process. Runtime scope, account, tool and consent checks continue
independently before launch and during execution.

## Read-only preflight before approval

Run as the actual nonprivileged worker account. First inspect the existing unit
locally; do not publish environment-file contents:

```bash
cd ~/ANTIC_Project/UPTIP/frontend
source .venv/bin/activate
git branch --show-current
git log -1 --format='%H%n%s'
git status --short
systemctl show uptip-execution-worker.service \
  -p User -p WorkingDirectory -p ExecStart -p ActiveState
systemctl cat uptip-execution-worker.service

export UPTIP_NIKTO_EXECUTABLE="$(readlink -f /usr/bin/nikto)"
test -x "$UPTIP_NIKTO_EXECUTABLE"
export UPTIP_NIKTO_SHA256="$(sha256sum "$UPTIP_NIKTO_EXECUTABLE" | cut -d ' ' -f 1)"
export UPTIP_NIKTO_VERSION=2.6.1
printf 'Executable: %s\nSHA-256: %s\nVersion: %s\n' \
  "$UPTIP_NIKTO_EXECUTABLE" "$UPTIP_NIKTO_SHA256" "$UPTIP_NIKTO_VERSION"
```

The canonical path may differ from `/usr/bin/nikto` if that is a symlink. No
binary hash is supplied by this repository or assumed from another machine.
The existing adapter verifies trusted ownership/permissions, exact hash and
version. Also review the root-owned Nikto installation/configuration/plugins.

Run the installed version probe in a disconnected, default-drop namespace. This
does not scan a target, select v2, open PostgreSQL or start a worker:

```bash
PYTHONPATH=backend python - <<'PY'
import os
from app.nikto_adapter import NiktoAdapter, NiktoConfig
from app.nikto_network_boundary import NamespaceBoundary
boundary = NamespaceBoundary()
adapter = NiktoAdapter(NiktoConfig(os.environ['UPTIP_NIKTO_EXECUTABLE'],
    os.environ['UPTIP_NIKTO_SHA256'], os.environ['UPTIP_NIKTO_VERSION']), boundary=boundary)
with boundary.restrict(None, None):
    adapter.verify()
print('Isolated pinned Nikto version probe passed; no scan or activation performed.')
PY
```

Failure leaves Nikto unavailable. Do not remove containment, capabilities,
seccomp, read-only filesystem or hash checks. Test under the service account
and its actual systemd restrictions as part of acceptance; an interactive-shell
pass alone does not prove the service can launch. The existing systemd sandbox
must remain intact.

Rerun local containment when prerequisites/context change:

```bash
UPTIP_NIKTO_CONTAINMENT_TEST=1 UPTIP_AUTHORIZED_TEST_IPV4=192.168.161.131 \
PYTHONPATH=backend python -m pytest -q backend/tests/test_nikto_network_boundary.py \
  -k kali_kernel_containment --tb=short --log-cli-level=WARNING
```

All nine must pass; tests create local listeners only. A live scan requires a
separate approval of scheme, exact port, address, assessment and acceptance scope.

## Prepare configuration for review (do not activate automatically)

The optional template is
`deploy/systemd/uptip-execution-worker-nikto.conf.example`. It resets only
ExecStart, preserves the documented Nmap arguments and adds the three Nikto
pins. It does not change User, Group, existing EnvironmentFile, sandbox settings,
database role, Restart or KillMode. Preserve any additional local Nmap limit
flags when rendering it. Never install an unresolved `__PYTHON__` placeholder.

Prepare a private candidate, inspect it and compare with the active command:

```bash
candidate=$(mktemp /tmp/uptip-nikto-dropin.XXXXXX.conf)
chmod 600 "$candidate"
sed 's|__PYTHON__|/home/menye/ANTIC_Project/UPTIP/frontend/.venv/bin/python|g' \
  deploy/systemd/uptip-execution-worker-nikto.conf.example > "$candidate"
cat "$candidate"
systemctl show uptip-execution-worker.service -p ExecStart --value
```

Review and add the three actual `UPTIP_NIKTO_EXECUTABLE`, `UPTIP_NIKTO_SHA256`,
`UPTIP_NIKTO_VERSION` values to the unit's existing protected EnvironmentFile
using `sudoedit` and its actual path. Do not assume `.env` is shell code or source
it. Do not store credentials or this machine's environment file in Git. Keep the
existing worker database URL/role and all Nmap settings unchanged.

Print the release identity for the approval record without activating it:

```bash
PYTHONPATH=backend python - <<'PY'
from app.nikto_profile import authority
p = authority(2)
print('UPTIP_NIKTO_POLICY_VERSION=2')
print('UPTIP_NIKTO_POLICY_DIGEST=' + p['digest'])
print('Approval reference must be supplied by the approving deployment operator.')
PY
```

**Stop here until operator approval.** After approval, manually place the exact
three policy settings in both backend and worker protected configurations,
including the actual approval reference. They are not credentials, but write
access constitutes deployment authority. Do not copy an example reference as
organizational approval.

Only in the approved maintenance window, after confirming existing processes
are terminated and unresolved work is accounted for, install the reviewed file:

```bash
(
set -eu
dropin=/etc/systemd/system/uptip-execution-worker.service.d/20-nikto.conf
test ! -e "$dropin" || { echo 'STOP: review the existing drop-in; do not overwrite.'; exit 1; }
sudo install -d -m 0755 /etc/systemd/system/uptip-execution-worker.service.d
sudo install -m 0644 "$candidate" "$dropin"
sudo systemd-analyze verify "$(systemctl show uptip-execution-worker.service -p FragmentPath --value)"
)
```

Run each command only after the preceding check succeeds. No service action is
performed by repository scripts. The following actions are **manual and require
the operator's final go-ahead**, not part of development execution:

```bash
sudo systemctl daemon-reload
sudo systemctl restart uptip-execution-worker.service
systemctl show uptip-execution-worker.service -p User -p ActiveState -p SubState
sudo journalctl -u uptip-execution-worker.service -n 80 --no-pager
```

Reload the API through its existing deployment mechanism too. This repository
does not invent an API service name or stop a running development server.
The worker's verified-Nikto log includes policy identity/version/digest; missing
or invalid optional Nikto configuration does not grant dispatch. Do not repeatedly
restart uncertain work. Never run a second worker or use a database owner role.

Only after successful installed-tool/service verification should the trusted
operator attest the existing Nikto capability, if not already current:

```bash
PYTHONPATH=backend python -m app.baseline_maintenance tool-state \
  Nikto enabled --capability http-server-assessment
```

This is an operator-controlled maintenance write, **not a development/test
command or permission to scan**. It is not run automatically. It does not create
an organizational approval, recommendation acceptance or execution consent.

## Controlled end-to-end acceptance

1. Obtain explicit approval of the exact local `http[s]://192.168.161.131:PORT/`,
   including the assessment and allowed port. Do not infer permission from IP
   ownership or earlier containment tests.
2. Use a current, trusted service observation and Testing assessment with valid
   scope and tool state. Review and Accept the real recommendation.
3. Open Start Test. Verify endpoint/profile and Ready state from the backend;
   explicitly confirm once. Capture the returned job ID without exposing tokens.
4. Verify exactly one job/event, Queued then Running, immutable profile version
   2, approval-bound consent and the existing one-process restriction. No live
   operation is authorized by a planning GET or Nmap scheduling consent.
5. View Details: inspect actual event history, completion/failure/uncertainty,
   termination flags and lazy integrity-checked original stdout/stderr. Do not
   treat output as normalized findings; no Nikto findings parser is added here.
6. Validate scope/consent loss, timeout and interruption with controlled fixtures
   before broader use. Never retry uncertain scans automatically. Existing
   Running uncertainty blocks both queues after restart.

Legacy v1 jobs/receipts are not rewritten, converted, deleted or dispatched under
v2. Readiness reports `recommended_existing_policy_stale` for incompatible
existing jobs; a current-version duplicate returns the original receipt. No new
job is silently created to get around historical uniqueness. Planner identities,
decisions and ZAP unavailability are preserved. The Recommendations projection
can say integrated/requires_start_review, but still reports no execution grant;
the separate Start contract remains authoritative.

No live scan, operational approval, worker restart or operational database change
was performed during this implementation. Python 3.13/PostgreSQL 18 and real
service-context Nikto acceptance remain operator checks on Kali.


## Implementation verification record

The disposable PostgreSQL harness described in `nikto-recommended-execution.md`
ran the same 27 listed backend files plus `backend/tests/test_nikto_activation.py`:
**499 passed, 9 skipped, 0 failed**, Python 3.12/PostgreSQL 16.2. The nine skips
are the explicit real nft/slirp containment parameter cases, not missing database
coverage. The operator's Kali report of nine passes is separate evidence.

After accepting the exact plain/v-prefixed/version-word 2.6.1 banners, the final
focused command was:

```bash
PYTHONPATH=backend .venv/bin/python -m pytest -q   backend/tests/test_nikto_activation.py backend/tests/test_nikto_adapter.py   backend/tests/test_nikto_profile.py backend/tests/test_tool_adapter_registry.py
```

Result: **45 passed**, including three additional exact-version banner cases;
this overlaps the broad run and must not be added to it as a disjoint count.
Unsupported versions, partial output and unverified termination remain rejected.
The full workflow fixtures now explicitly select v2 with a disposable test
approval, rather than mutating v1's policy to simulate permission.

`npm test -- --run`: final **316 passed**, 16 files. The first frontend run had
315 passes and one failure in the unchanged Testing Completion stale-dialog
assertion. It passed unchanged on the full rerun and a targeted name-filtered
run (1 passed, 22 filtered/skipped). No assertion was removed and no completion
production code was changed to hide that timing issue.

`npm run lint`, `npm run build` (TypeScript and Vite),
`.venv/bin/python -m compileall -q backend/app backend/migrations backend/tests`
and `git diff --check` passed. Existing Starlette/httpx deprecation, imported
mapped-class collection and harness runtime-directory warnings remain. npm also
reported its inherited http-proxy setting and jsdom performance guidance.

No real installed Nikto/service-context probe or live scan ran here. No
operational configuration or database was accessed. Python 3.13/PostgreSQL 18,
actual worker sandbox compatibility, visual browser acceptance and local
endpoint-specific end-to-end acceptance remain Kali checks. Captured Nikto
output still does not implement normalized findings or clear the existing
missing-processing Testing Completion blocker.

## Changed files and purpose

| File | Purpose |
| --- | --- |
| `backend/app/config.py` | Optional exact deployment selection and approval reference. |
| `backend/app/nikto_profile.py` | Immutable v1 compatibility, v2 definition/integrity and explicit selection gates. |
| `backend/app/nikto_adapter.py` | Release-bound fixed arguments and exact supported version banner formats. |
| `backend/app/execution_worker.py` | Sanitized selected-policy diagnostics; optional invalid Nikto config cannot suppress Nmap initialization. |
| `backend/app/recommended_test_consumer.py` | Reject unsupported/stale plans; require selected v2 and enforced boundary. |
| `backend/app/recommended_test_authorization.py` | Bind selected deployment identity into fresh creator consent. |
| `backend/app/testing_routes.py` | Version-aware readiness, Start and legacy-job rejection without rewriting receipts. |
| `backend/app/recommendation_eligibility.py` | Truthful read-only explicit-Start requirement when Nikto is integrated. |
| `backend/app/testing_completion_service.py` | Project current integration state without changing planner IDs or review history. |
| `src/services/testing.ts` | Strictly validate the new Nikto-only planning status without granting execution. |
| `src/components/StartRecommendedTest.test.tsx` | Activated Nikto status contract and continued ZAP denial. |
| `backend/tests/test_nikto_workflow.py` | Real v2 test configuration, legacy jobs, approval changes, scope/port/tool constraints. |
| `backend/tests/test_nikto_activation.py` | Explicit selection, integrity, pin/version failure, worker config and drop-in regressions. |
| `deploy/systemd/uptip-execution-worker-nikto.conf.example` | Optional reviewed drop-in for the single existing worker. |
| `docs/nikto-recommended-execution.md` | Link historical guarded status to current operator-controlled v2 documentation. |
| `docs/nikto-activation.md` | Approval boundary, read-only preflight, manual deployment and acceptance procedure. |
