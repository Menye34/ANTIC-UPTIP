"""Explicit creator confirmation of exact TCP ports; no automatic dispatch."""
from datetime import datetime, timedelta, timezone
import hmac
from uuid import UUID, uuid4
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, StrictInt, StrictBool
from sqlalchemy import select, text
from sqlalchemy.orm import Session
from .assessment_routes import analyst
from .baseline_catalog import fingerprint
from .config import get_settings
from .database import get_db
from .models import (Assessment, AssessmentStartAuthorization, BaselineExecutionRequest,
                     ServiceDiscoveryConsent, ServiceDiscoveryRevocation, User, ExecutionEvent)
from .routes import trusted_origin
from .security import session_csrf
from .service_discovery import preparation
from .nmap_service_profile import canonical_ports

router = APIRouter(prefix='/api/v1/assessments/{assessment_id}/testing')


class ConfirmService(BaseModel):
    model_config = ConfigDict(extra='forbid')
    target_id: UUID
    ports: list[StrictInt]
    confirmed: StrictBool


def guard(request, db, assessment_id, user):
    settings = get_settings()
    cookie = request.cookies.get(settings.cookie_name, '')
    if not cookie or not trusted_origin(request) or not hmac.compare_digest(
            request.headers.get('x-csrf-token', ''), session_csrf(settings, cookie)):
        raise HTTPException(403)
    db.execute(select(User.id).where(User.id == user.id).with_for_update())
    assessment = db.scalar(select(Assessment).where(Assessment.id == assessment_id)
                           .with_for_update().execution_options(populate_existing=True))
    if assessment is None or assessment.creator_id != user.id:
        raise HTTPException(404)
    if assessment.status != 'Testing':
        raise HTTPException(409, 'assessment_not_testing')
    return assessment


def receipt(row):
    return {'execution_id': row.request_id, 'assessment_id': row.assessment_id,
            'target_id': row.target_id, 'consent_digest': row.digest,
            'expires_at': row.expires_at.astimezone(timezone.utc), 'status': 'Queued', 'execution_authorized': False}


@router.post('/service-discovery', status_code=201)
def schedule(assessment_id: UUID, body: ConfirmService, request: Request, response: Response,
             idempotency_key: UUID = Header(alias='Idempotency-Key'),
             user: User = Depends(analyst), db: Session = Depends(get_db)):
    try:
        guard(request, db, assessment_id, user)
        if body.confirmed is not True:
            raise HTTPException(422, 'explicit_confirmation_required')
        try:
            ports = canonical_ports(body.ports)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        prior = db.scalar(select(ServiceDiscoveryConsent).where(
            ServiceDiscoveryConsent.assessment_id == assessment_id,
            ServiceDiscoveryConsent.idempotency_key == idempotency_key))
        if prior is not None:
            if prior.target_id != body.target_id or prior.snapshot['preparation']['plan']['ports'] != ports:
                raise HTTPException(409, 'idempotency_conflict')
            response.status_code = 200
            result = receipt(prior)
            db.commit()
            return result
        auth = db.scalar(select(AssessmentStartAuthorization).where(
            AssessmentStartAuthorization.assessment_id == assessment_id))
        host = db.scalar(select(BaselineExecutionRequest).where(
            BaselineExecutionRequest.assessment_id == assessment_id,
            BaselineExecutionRequest.target_id == body.target_id,
            BaselineExecutionRequest.profile_id == 'network-discovery'))
        if auth is None or host is None or host.authorization_id != auth.id:
            raise HTTPException(409, 'authorized_host_target_required')
        db.execute(text('SELECT public.lock_execution_dispatch_sources(:request_id)'), {'request_id': host.id})
        if db.scalar(select(BaselineExecutionRequest.id).where(
                BaselineExecutionRequest.authorization_id == auth.id,
                BaselineExecutionRequest.target_id == body.target_id,
                BaselineExecutionRequest.profile_id == 'service-discovery')):
            raise HTTPException(409, 'service_discovery_already_scheduled')
        try:
            prep = preparation(db, host, ports)
        except (ValueError, KeyError, TypeError) as exc:
            raise HTTPException(409, 'service_preparation_unavailable') from exc
        created = datetime.now(timezone.utc)
        expiry = created + timedelta(hours=1)
        snapshot = {'schema_version': 1, 'actor_id': str(user.id), 'confirmed': True,
                    'expires_at': expiry.isoformat(), 'preparation': prep}
        digest = fingerprint(snapshot)
        queued = BaselineExecutionRequest(id=uuid4(), assessment_id=assessment_id,
            authorization_id=auth.id, target_id=body.target_id,
            profile_id='service-discovery', profile_version=1, tool='Nmap', activity='Service Discovery',
            status='Queued', authorized_activity={'target_value': prep['plan']['target'],
                'service_consent_digest': digest, 'scheduling_preparation': {
                    'plan': prep['plan'], 'parameter_digest': prep['plan']['parameter_digest']}})
        db.add(queued)
        db.flush()
        row = ServiceDiscoveryConsent(request_id=queued.id, assessment_id=assessment_id,
            target_id=body.target_id, actor_id=user.id, idempotency_key=idempotency_key,
            snapshot=snapshot, digest=digest, created_at=created, expires_at=expiry)
        db.add(row)
        db.flush()
        db.add(ExecutionEvent(request_id=queued.id, assessment_id=assessment_id,
            target_id=body.target_id, actor_id=user.id, operation_id=idempotency_key,
            event_type='service_discovery_confirmed', reason_code='explicit_target_and_ports',
            details={'consent_digest': digest, 'policy_digest': prep['policy']['digest']},
            occurred_at=created))
        result = receipt(row)
        db.commit()
        return result
    except Exception:
        db.rollback()
        raise


@router.post('/service-discovery/{execution_id}/revoke')
def revoke(assessment_id: UUID, execution_id: UUID, request: Request,
           user: User = Depends(analyst), db: Session = Depends(get_db)):
    try:
        guard(request, db, assessment_id, user)
        consent = db.get(ServiceDiscoveryConsent, execution_id)
        if consent is None or consent.assessment_id != assessment_id:
            raise HTTPException(404)
        if db.get(ServiceDiscoveryRevocation, execution_id) is None:
            db.add(ServiceDiscoveryRevocation(request_id=execution_id, actor_id=user.id))
            db.add(ExecutionEvent(request_id=execution_id, assessment_id=assessment_id,
                target_id=consent.target_id, actor_id=user.id, operation_id=uuid4(),
                event_type='service_discovery_revoked', reason_code='creator_revoked',
                details={}, occurred_at=datetime.now(timezone.utc)))
        db.commit()
        return {'revoked': True}
    except Exception:
        db.rollback()
        raise
