"""Conservative v1 consolidation. Facts are not automatically vulnerabilities.

Only explicitly supported issue observations are promoted; host/service discovery
remains factual evidence for later rules. No heuristic severity escalation.
"""
from hashlib import sha256
import json
from sqlalchemy import select
from .models import SecurityObservation, ScannerEvidence, ResultProcessingOutcome, BaselineExecutionRequest
from .findings_models import ConsolidatedFinding, FindingObservation

RULE_VERSION = 'findings-v1'
SEVERITIES = frozenset({'Critical', 'High', 'Medium', 'Low'})
REQUIRED = ('title', 'severity', 'affected_target', 'description', 'impact',
            'security_control', 'observed_condition', 'detected_issue', 'remediation')
# An explicit vulnerability/issue producer is required. Discovery-only observations
# must not be interpreted as security findings.
SUPPORTED_TYPES = frozenset({'security_issue'})


def normalize(observation, evidence, request):
    if observation.observation_type not in SUPPORTED_TYPES or observation.is_partial or evidence.is_partial:
        return None
    data = observation.data
    if not isinstance(data, dict) or any(not isinstance(data.get(k), str) or not data[k].strip() for k in REQUIRED):
        return None
    if data['severity'] not in SEVERITIES or not isinstance(data.get('issue_key'), str) or not data['issue_key'].strip():
        return None
    if data['affected_target'] != request.authorized_activity.get('target_value'):
        return None
    identity = {'assessment': str(observation.assessment_id), 'target': str(observation.target_id),
                'issue_key': data['issue_key'].strip().lower(), 'endpoint': data['affected_target']}
    key = sha256(json.dumps(identity, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return key, {k: data[k].strip() for k in REQUIRED}


def candidates(db, assessment_id, *, finding_id=None):
    """Enumerate eligible baseline candidates without writing records.

    Only successful complete processing of completed requests and matching original
    evidence is trusted. An observation is never attached to another assessment.
    """
    rows = db.execute(select(SecurityObservation, ScannerEvidence, ResultProcessingOutcome, BaselineExecutionRequest)
        .join(ScannerEvidence, ScannerEvidence.id == SecurityObservation.evidence_id)
        .join(ResultProcessingOutcome, ResultProcessingOutcome.id == SecurityObservation.processing_id)
        .join(BaselineExecutionRequest, BaselineExecutionRequest.id == SecurityObservation.request_id)
        .where(SecurityObservation.assessment_id == assessment_id,
                (
                    select(FindingObservation.observation_id)
                    .where(
                        FindingObservation.assessment_id == assessment_id,
                        FindingObservation.finding_id == finding_id,
                        FindingObservation.observation_id == SecurityObservation.id,
                    )
                    .exists()
                    if finding_id is not None else True
                ),
               ScannerEvidence.assessment_id == assessment_id,
               ResultProcessingOutcome.assessment_id == assessment_id,
               BaselineExecutionRequest.assessment_id == assessment_id,
               ScannerEvidence.id == ResultProcessingOutcome.evidence_id,
               SecurityObservation.evidence_id == ResultProcessingOutcome.evidence_id,
               SecurityObservation.request_id == ResultProcessingOutcome.request_id,
               SecurityObservation.target_id == ScannerEvidence.target_id,
               SecurityObservation.target_id == BaselineExecutionRequest.target_id,
               ResultProcessingOutcome.status == 'Succeeded',
               ResultProcessingOutcome.is_partial.is_(False),
               ScannerEvidence.is_partial.is_(False),
               BaselineExecutionRequest.status == 'Completed')
        .order_by(SecurityObservation.collected_at, SecurityObservation.id)).all()
    for observation, evidence, processing, request in rows:
        item = normalize(observation, evidence, request)
        if item is None:
            continue
        key, fields = item
        yield observation, evidence, request, key, fields


def candidate_keys(db, assessment_id):
    """Return unique eligible baseline finding identities."""
    return {
        key for _, _, _, key, _ in candidates(db, assessment_id)
    }


def consolidate(db, assessment_id):
    """Caller owns transaction and assessment row lock.
    Repeated calls are idempotent.
    """
    created = 0
    for observation, evidence, request, key, fields in candidates(
        db, assessment_id
    ):
        linked = db.scalar(
            select(FindingObservation).where(FindingObservation.observation_id == observation.id))
        if linked:
            continue
        finding = db.scalar(select(ConsolidatedFinding).where(
            ConsolidatedFinding.assessment_id == assessment_id, ConsolidatedFinding.identity_key == key))
        if finding is None:
            finding = ConsolidatedFinding(assessment_id=assessment_id, identity_key=key,
                rule_version=RULE_VERSION, title=fields['title'], severity=fields['severity'],
                affected_target=fields['affected_target'], source=evidence.tool,
                source_test=request.activity, description=fields['description'], impact=fields['impact'],
                security_control=fields['security_control'], observed_condition=fields['observed_condition'],
                detected_issue=fields['detected_issue'], remediation=fields['remediation'])
            db.add(finding)
            db.flush()
            created += 1
        elif finding.severity != fields['severity'] or finding.title != fields['title']:
            # Conflicting severity/title is not silently merged.
            continue
        db.add(FindingObservation(finding_id=finding.id, observation_id=observation.id,
            assessment_id=assessment_id, match_reason='exact_issue_target'))
    db.flush()
    return created
