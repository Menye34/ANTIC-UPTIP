"""The recommendation schema must not be accepted by the baseline worker."""
from sqlalchemy.schema import CheckConstraint, ForeignKeyConstraint

from app.models import BaselineExecutionRequest
from app.recommendation_authorization_models import (
    RecommendationAuthorizationRecord, RecommendationExecutionRequest,
)


def test_recommendation_tables_are_separate_from_baseline_dispatch():
    assert RecommendationAuthorizationRecord.__tablename__ != BaselineExecutionRequest.__tablename__
    assert RecommendationExecutionRequest.__tablename__ != BaselineExecutionRequest.__tablename__
    assert 'authorization_id' in RecommendationExecutionRequest.__table__.columns
    assert 'source_observation_id' in RecommendationAuthorizationRecord.__table__.columns
    assert 'source_evidence_id' in RecommendationAuthorizationRecord.__table__.columns


def test_execution_request_has_no_queued_or_running_status():
    checks = [item.sqltext.text for item in RecommendationExecutionRequest.__table__.constraints
              if isinstance(item, CheckConstraint)]
    assert any('PendingVerification' in sql and 'Blocked' in sql and 'Cancelled' in sql
               and 'Queued' not in sql and 'Running' not in sql for sql in checks)


def test_execution_request_binds_authorization_assessment_and_target():
    constraints = [item for item in RecommendationExecutionRequest.__table__.constraints
                   if isinstance(item, ForeignKeyConstraint)]
    assert any({column.parent.name for column in constraint.elements}
               == {'authorization_id', 'assessment_id', 'target_id'} for constraint in constraints)
