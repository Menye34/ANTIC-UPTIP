"""Explicit regression harness for the former execution-approval contract.

These tests preserve independent execution-policy/evidence/dependency validation.
The public readiness endpoint now uses scheduling evaluation; its real default
is tested without this override in test_scheduling_start.py. Historical receipts
remain replayable, but old review tokens are not accepted by the new default.
"""
import pytest


@pytest.fixture(autouse=True)
def legacy_execution_endpoint_contract(monkeypatch):
    from app import assessment_routes, assessment_readiness
    monkeypatch.setattr(assessment_routes, 'evaluate_readiness',
                        assessment_readiness.evaluate_execution_readiness)
