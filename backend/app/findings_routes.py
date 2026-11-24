"""Assessment-scoped read-only F-01 overview. No result generation on GET."""
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select, case
from sqlalchemy.orm import Session
from .assessment_routes import accessible, analyst
from .database import get_db
from .models import Assessment, User
from .findings_models import ConsolidatedFinding

router = APIRouter(prefix='/api/v1/assessments/{assessment_id}/findings')


class FindingSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    title: str
    severity: str
    affected_target: str
    source: str


class FindingDetail(FindingSummary):
    source_test: str
    description: str
    impact: str
    security_control: str
    observed_condition: str
    detected_issue: str
    remediation: str


class FindingsOverview(BaseModel):
    assessment_id: UUID
    lifecycle_status: str
    total: int
    counts: dict[str, int]
    findings: list[FindingSummary]


@router.get('', response_model=FindingsOverview)
def findings_overview(assessment_id: UUID, user: User = Depends(analyst),
                      db: Session = Depends(get_db)):
    assessment = db.scalar(select(Assessment).where(Assessment.id == assessment_id, accessible(user)))
    if assessment is None:
        raise HTTPException(404)
    findings = db.scalars(select(ConsolidatedFinding)
        .where(ConsolidatedFinding.assessment_id == assessment_id)
        .order_by(case((ConsolidatedFinding.severity == 'Critical', 0),
                       (ConsolidatedFinding.severity == 'High', 1),
                       (ConsolidatedFinding.severity == 'Medium', 2),
                       else_=3), ConsolidatedFinding.created_at, ConsolidatedFinding.id)).all()
    return FindingsOverview(assessment_id=assessment_id, lifecycle_status=assessment.status,
        total=len(findings),
        counts={severity: sum(f.severity == severity for f in findings)
                for severity in ('Critical', 'High', 'Medium', 'Low')},
        findings=[FindingSummary.model_validate(f) for f in findings])


@router.get('/{finding_id}', response_model=FindingDetail)
def finding_detail(assessment_id: UUID, finding_id: UUID,
                   user: User = Depends(analyst), db: Session = Depends(get_db)):
    assessment = db.scalar(select(Assessment.id).where(
        Assessment.id == assessment_id, accessible(user)))
    if assessment is None:
        raise HTTPException(404)
    finding = db.scalar(select(ConsolidatedFinding).where(
        ConsolidatedFinding.id == finding_id,
        ConsolidatedFinding.assessment_id == assessment_id))
    if finding is None:
        raise HTTPException(404)
    return FindingDetail.model_validate(finding)
