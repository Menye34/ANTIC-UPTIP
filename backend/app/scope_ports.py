"""Exact-address port consent. Address/subnet membership alone grants no ports."""
from sqlalchemy import select
from .models import ScopeEntry
from .nmap_service_profile import canonical_ports


def authorized_ports(db, assessment_id, target):
    ports = db.scalar(select(ScopeEntry.tcp_ports).where(
        ScopeEntry.assessment_id == assessment_id, ScopeEntry.kind == 'IP address',
        ScopeEntry.normalized_value == target))
    return canonical_ports(ports) if ports else []
