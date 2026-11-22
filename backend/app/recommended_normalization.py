"""Offline, idempotent normalization of durably recorded recommended Nikto output."""
from datetime import datetime, timezone
from hashlib import sha256
from sqlalchemy import select
from .nikto_normalizer import normalize, VERSION
from .recommended_test_queue import RecommendedTestJob
from .recommended_normalization_models import RecommendedProcessingOutcome, RecommendedObservation

PROCESSOR = 'nikto-text'


def process_job(db, job_id):
    """Caller owns a transaction. Never launches a scanner or changes job status."""
    job = db.scalar(select(RecommendedTestJob).where(RecommendedTestJob.id == job_id).with_for_update())
    if job is None or job.status != 'Completed' or job.tool != 'Nikto':
        return None
    if (job.termination_verified is not True or job.output_partial is not False
            or not isinstance(job.stdout, bytes) or not isinstance(job.stderr, bytes)
            or not isinstance(job.output_digest, str)
            or sha256(job.stdout + b'\x00' + job.stderr).hexdigest() != job.output_digest):
        return None
    existing = db.scalar(select(RecommendedProcessingOutcome).where(
        RecommendedProcessingOutcome.job_id == job.id,
        RecommendedProcessingOutcome.processor == PROCESSOR,
        RecommendedProcessingOutcome.processor_version == VERSION,
        RecommendedProcessingOutcome.output_digest == job.output_digest))
    if existing is not None:
        return existing
    now = datetime.now(timezone.utc)
    error = None
    try:
        observations = normalize(job.stdout, target=job.execution_plan['target'],
                                 port=job.execution_plan['port'], scheme=job.execution_plan['scheme'])
    except (ValueError, KeyError, TypeError):
        observations = []
        error = 'nikto_normalization_failed'
    outcome = RecommendedProcessingOutcome(
        job_id=job.id, assessment_id=job.assessment_id, target_id=job.target_id,
        processor=PROCESSOR, processor_version=VERSION, output_digest=job.output_digest,
        status='Failed' if error else 'Succeeded', error_code=error,
        observation_count=len(observations), finished_at=now)
    db.add(outcome)
    db.flush()
    for item in observations:
        db.add(RecommendedObservation(
            processing_id=outcome.id, job_id=job.id,
            assessment_id=job.assessment_id, target_id=job.target_id,
            observation_type=item['type'], data=item['data'],
            deduplication_key=item['deduplication_key'],
            collected_at=job.finished_at or now, processed_at=now, is_partial=False))
    db.flush()
    return outcome
