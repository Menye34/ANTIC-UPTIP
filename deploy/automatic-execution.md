# Automatic authorized execution worker (Phase 1)

The current backend already persists baseline requests and polls the queue continuously
when `app.execution_worker` is started without `--once`. FastAPI must **not**
spawn scanners, start the worker, or bypass `dispatch_verification.verify`.

## Scope and limitations

- This service supervises the **existing Nmap-only** execution worker. It does
  not enable ZAP/OpenVAS or other scan profiles. Their tool-specific adapters,
  policy verification, result parsers, and recovery semantics require separate
  implementation and tests.
- A request is eligible only after Start Assessment has committed its authorized
  baseline request. The worker revalidates the assessment, target, profile,
  permissions, and authorization before launching.
- An uncertain scan is **not** automatically retried. An expired or lost
  attempt requires explicit recovery review.
- The worker's global advisory lock permits only one live worker per database.

## Prerequisites

1. Use the existing non-admin `uptip_worker` PostgreSQL role with only the
   necessary permissions. Never point the worker at the migration/admin role.
2. Ensure the scanner executable is root-owned, not writable by others,
   capability-free, and pinned to its verified SHA-256 and version.
3. Review all queued requests and scope/authorization before enabling dispatch.
4. Use a separate root-owned environment file (mode 0600) containing
   `UPTIP_DATABASE_URL`, `UPTIP_RATE_KEY`, `UPTIP_NMAP_EXECUTABLE`, `UPTIP_NMAP_SHA256`,
   `UPTIP_NMAP_VERSION`, `UPTIP_EVIDENCE_DIRECTORY`. The worker's\n`Settings` also reads the existing application environment settings; preserve\nthe required settings without copying application admin or migration secrets.\nDo not commit the environment file.
5. Evidence directory must exist and be writable only by the worker (0700).

## systemd installation on Kali

Copy `deploy/systemd/uptip-execution-worker.service.example` to a temporary
file and replace all placeholders:

- `__USER__`: unprivileged Kali account that runs the worker.
- `__BACKEND_DIR__`: absolute path to `frontend/backend`.
- `__PYTHON__`: absolute path to the project virtualenv Python executable.
- `__WORKER_ENV__`: absolute path to the root-owned private environment file.
- `__EVIDENCE_DIR__`: same absolute directory as `UPTIP_EVIDENCE_DIRECTORY`.

Then install the reviewed unit as
`/etc/systemd/system/uptip-execution-worker.service` with root ownership,
run `sudo systemctl daemon-reload`, and start it with
`sudo systemctl start uptip-execution-worker.service`.
Inspect `sudo systemctl status uptip-execution-worker.service` and
`sudo journalctl -u uptip-execution-worker.service -n 100 --no-pager`.
**Only after a safe local test**, opt in to reboot startup with
`sudo systemctl enable uptip-execution-worker.service`.

To stop automatic dispatch: `sudo systemctl stop uptip-execution-worker.service`.
Stopping the service is not a substitute for revoking authorization or
cancelling running scans; inspect actual process and attempt states.

## End-to-end verification (authorized lab targets only)

1. Start the worker service and confirm it remains active.
2. Start an assessment containing only explicitly authorized lab targets.
3. Confirm the committed request changes from Queued to Running to Completed
   (or a documented blocked/failed/recovery state).
4. Confirm the attempt, audit events, evidence hashes and original tool output
   were persisted; verify the API read views.
5. Restart the service; confirm it does not duplicate or retry completed or
   uncertain executions.
6. Disable the tool/revoke authorization in a controlled test and confirm
   subsequent dispatch is blocked.

## Next phase: multiple tools

Introduce an explicit, fail-closed adapter registry keyed by approved tool and
profile, with per-tool launch/poll/cancel/result contracts. Keep tool-specific
authorization, evidence format, external job IDs, and recovery policy distinct.
Do not treat a generic API response as proof that a scanner has terminated.
