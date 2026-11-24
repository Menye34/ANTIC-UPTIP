"""Unified candidate counting and findings consolidation."""

from .findings_processing import (
    candidate_keys as baseline_candidate_keys,
    consolidate as consolidate_baseline,
)
from .nikto_findings_processing import (
    candidate_keys as nikto_candidate_keys,
    consolidate_nikto,
)


def candidate_keys(db, assessment_id):
    """Return unique eligible finding identities across supported sources."""
    return (
        baseline_candidate_keys(db, assessment_id)
        | nikto_candidate_keys(db, assessment_id)
    )


def candidate_count(db, assessment_id):
    """Count eligible unique candidates without persisting findings."""
    return len(candidate_keys(db, assessment_id))


def consolidate_findings(db, assessment_id):
    """Persist supported findings and evidence relationships.

    Caller must hold the assessment row lock and own the transaction.
    """
    baseline_created = consolidate_baseline(db, assessment_id)
    nikto_created = consolidate_nikto(db, assessment_id)

    return baseline_created + nikto_created
