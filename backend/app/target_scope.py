from ipaddress import IPv4Address, IPv4Network

from sqlalchemy import select

from .models import AssessmentTarget, ScopeEntry


def scope_entries(db, assessment_id):
    return db.execute(select(ScopeEntry.normalized_value, ScopeEntry.kind)
                      .where(ScopeEntry.assessment_id == assessment_id)).all()


def matches(value, kind, boundary, boundary_kind):
    # Exact hostname and URL matches grant no permissions to related names, paths or hosts.
    if kind == boundary_kind and value == boundary:
        return True
    if boundary_kind != 'Subnet':
        return False
    if kind == 'IP address':
        return IPv4Address(value) in IPv4Network(boundary)
    if kind == 'Subnet':
        return IPv4Network(value).subnet_of(IPv4Network(boundary))
    return False


def classify(value, kind, boundaries):
    if any(matches(value, kind, boundary, boundary_kind) for boundary, boundary_kind in boundaries):
        return 'in_scope', 'Matched an authorized scope entry.'
    return 'out_of_scope', 'No authorized scope entry covers this target.'


def reclassify_targets(db, assessment, previous_boundaries):
    """Called inside the same parent lock and transaction as the scope change."""
    boundaries = scope_entries(db, assessment.id)
    removed = set(previous_boundaries) - set(boundaries)
    added = set(boundaries) - set(previous_boundaries)
    targets = db.scalars(select(AssessmentTarget).where(AssessmentTarget.assessment_id == assessment.id))
    affected = 0
    for target in targets:
        status, reason = classify(target.normalized_value, target.kind, boundaries)
        if (target.scope_status != status or target.scope_revision != assessment.scope_revision - 1
                or any(matches(target.normalized_value, target.kind, value, kind) for value, kind in removed | added)):
            affected += 1
        target.scope_status = status
        target.classification_reason = reason
        target.scope_revision = assessment.scope_revision
    return affected
