"""Bounded result recording for the independent recommended-test queue.

The caller must already hold the job row lock. This module never launches tools,
changes authorization, or turns an unverified job into an executable request.
"""
from datetime import datetime, timezone
from hashlib import sha256

MAX_STREAM_BYTES = 5 * 1024 * 1024


def mark_running(job, *, now=None):
    if job.status != 'Queued':
        raise ValueError('recommended_job_not_queued')
    job.status = 'Running'
    job.started_at = now or datetime.now(timezone.utc)


def record_outcome(job, outcome, *, now=None):
    """Persist complete/partial scanner output without interpreting it as findings.

    A successful process exit is not automatically a validated security finding.
    Normalization and evidence linkage must be performed separately.
    """
    if job.status != 'Running':
        raise ValueError('recommended_job_not_running')
    stdout, stderr = outcome.stdout, outcome.stderr
    if not isinstance(stdout, bytes) or not isinstance(stderr, bytes):
        raise ValueError('invalid_scanner_output')
    if len(stdout) + len(stderr) > MAX_STREAM_BYTES:
        raise ValueError('scanner_output_exceeds_limit')
    if outcome.exit_code is not None and (type(outcome.exit_code) is not int or not -255 <= outcome.exit_code <= 255):
        raise ValueError('invalid_exit_code')
    if not isinstance(outcome.reason, str) or not outcome.reason.isascii() or len(outcome.reason) > 120:
        raise ValueError('invalid_execution_reason')
    job.stdout = stdout
    job.stderr = stderr
    job.output_digest = sha256(stdout + b'\x00' + stderr).hexdigest()
    job.termination_verified = outcome.terminated is True
    job.output_partial = outcome.partial is True
    job.exit_code = outcome.exit_code
    if not outcome.terminated:
        # Running means unresolved ownership here, never proof of termination.
        job.failure_reason = 'termination_unverified'
        return job.status
    job.finished_at = now or datetime.now(timezone.utc)
    success = outcome.exit_code == 0 and outcome.reason == 'scanner_exited' and outcome.terminated and not outcome.partial
    job.status = 'Completed' if success else 'Failed'
    job.failure_reason = None if success else outcome.reason
    return job.status
