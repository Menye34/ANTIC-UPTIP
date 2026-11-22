"""Backfill completed Nikto jobs without launching scanners.

Run from backend directory after applying migration 0028:
    python -m scripts.backfill_nikto_observations

Uses the configured database role and existing output-integrity checks.
"""
from sqlalchemy import select
from app.database import session_factory
from app.recommended_test_queue import RecommendedTestJob
from app.recommended_normalization import process_job


def main():
    factory = session_factory()
    with factory() as db:
        ids = db.scalars(select(RecommendedTestJob.id).where(
            RecommendedTestJob.tool == 'Nikto',
            RecommendedTestJob.status == 'Completed').order_by(RecommendedTestJob.created_at)).all()
    succeeded = skipped = 0
    for job_id in ids:
        with factory.begin() as db:
            outcome = process_job(db, job_id)
            if outcome is None:
                skipped += 1
            else:
                succeeded += 1
    print(f'Nikto normalization checked: {len(ids)}; processed/already present: {succeeded}; skipped: {skipped}')


if __name__ == '__main__':
    main()
