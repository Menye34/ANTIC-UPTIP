"""Assessment-scoped consolidation of stored Nikto observations."""

import json
from hashlib import sha256
from ipaddress import ip_address

from sqlalchemy import select, and_

from .nikto_findings import classify, RULE_VERSION
from .findings_models import (
    ConsolidatedFinding,
    FindingRecommendedObservation,
)
from .recommended_normalization_models import (
    RecommendedObservation as Observation,
    RecommendedProcessingOutcome as Processing,
)
from .recommended_test_queue import RecommendedTestJob as Job
from .recommended_testing_reads import output_verified


def normalize_candidate(observation):
    data = observation.data

    fields = classify(
        observation.observation_type,
        data,
        observation.is_partial,
    )

    if fields is None:
        return None

    address = data.get("address")
    port = data.get("port")
    scheme = data.get("scheme")
    path = data.get("path")

    if not isinstance(address, str):
        return None

    try:
        address = ip_address(address)
    except ValueError:
        return None

    if type(port) is not int or not 1 <= port <= 65535:
        return None

    if not isinstance(path, str) or not path.startswith("/"):
        return None

    if path.startswith("//") or any(
        c.isspace() or ord(c) < 32 or c in "\\#"
        for c in path
    ):
        return None

    host = f"[{address}]" if address.version == 6 else str(address)

    endpoint = f"{scheme}://{host}:{port}{path}"

    if len(endpoint) > 1024:
        return None

    issue_key = fields.pop("issue_key")

    identity = {
        "assessment": str(observation.assessment_id),
        "target": str(observation.target_id),
        "issue_key": issue_key,
        "endpoint": endpoint,
    }

    key = sha256(
        json.dumps(
            identity,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()

    return key, {
        **fields,
        "affected_target": endpoint,
    }



def matches_authorized_endpoint(observation, plan):
    """Reject observations outside the original execution endpoint."""

    if not isinstance(plan, dict):
        return False

    data = observation.data

    if not isinstance(data, dict):
        return False

    target = plan.get("target")
    address = data.get("address")

    if not isinstance(target, str) or not isinstance(address, str):
        return False

    try:
        if ip_address(target) != ip_address(address):
            return False
    except ValueError:
        return False

    port = plan.get("port")
    observed_port = data.get("port")

    if type(port) is not int or not 1 <= port <= 65535:
        return False

    if type(observed_port) is not int or observed_port != port:
        return False

    scheme = plan.get("scheme")

    if scheme not in ("http", "https"):
        return False

    return data.get("scheme") == scheme


def candidates(db, assessment_id, *, finding_id=None):
    """Read eligible observations without modifying stored results."""

    rows = db.execute(
        select(Observation, Job.execution_plan)
        .join(
            Processing,
            and_(
                Processing.id == Observation.processing_id,
                Processing.job_id == Observation.job_id,
                Processing.assessment_id == Observation.assessment_id,
                Processing.target_id == Observation.target_id,
            ),
        )
        .join(
            Job,
            and_(
                Job.id == Observation.job_id,
                Job.assessment_id == Observation.assessment_id,
                Job.target_id == Observation.target_id,
            ),
        )
        .where(
            Observation.assessment_id == assessment_id,
                (
                    select(FindingRecommendedObservation.observation_id)
                    .where(
                        FindingRecommendedObservation.assessment_id == assessment_id,
                        FindingRecommendedObservation.finding_id == finding_id,
                        FindingRecommendedObservation.observation_id == Observation.id,
                    )
                    .exists()
                    if finding_id is not None else True
                ),
            Observation.is_partial.is_(False),
            Processing.status == "Succeeded",
            Processing.processor == "nikto-text",
            Processing.output_digest == Job.output_digest,
            Job.status == "Completed",
            Job.tool == "Nikto",
            Job.termination_verified.is_(True),
            Job.output_partial.is_(False),
            output_verified(),
        )
        .order_by(
            Observation.collected_at,
            Observation.id,
        )
    ).all()

    for observation, plan in rows:
        if not matches_authorized_endpoint(observation, plan):
            continue

        item = normalize_candidate(observation)

        if item is not None:
            key, fields = item
            yield observation, key, fields


def candidate_keys(db, assessment_id):
    """Return deduplicated candidate finding identities."""

    return {
        key
        for _, key, _ in candidates(db, assessment_id)
    }


def consolidate_nikto(db, assessment_id):
    """Persist candidates and evidence links.

    Caller must hold the assessment row lock and own the transaction.
    """

    created = 0

    for observation, key, fields in candidates(db, assessment_id):

        linked = db.scalar(
            select(FindingRecommendedObservation).where(
                FindingRecommendedObservation.observation_id
                == observation.id
            )
        )

        if linked is not None:
            continue

        finding = db.scalar(
            select(ConsolidatedFinding).where(
                ConsolidatedFinding.assessment_id == assessment_id,
                ConsolidatedFinding.identity_key == key,
            )
        )

        if finding is None:
            finding = ConsolidatedFinding(
                assessment_id=assessment_id,
                identity_key=key,
                rule_version=RULE_VERSION,
                source="Nikto",
                source_test="HTTP Server Assessment",
                **fields,
            )

            db.add(finding)
            db.flush()

            created += 1

        elif (
            finding.title != fields["title"]
            or finding.severity != fields["severity"]
        ):
            continue

        db.add(
            FindingRecommendedObservation(
                finding_id=finding.id,
                observation_id=observation.id,
                assessment_id=assessment_id,
                match_reason="exact_issue_target",
            )
        )

        db.flush()

    return created
