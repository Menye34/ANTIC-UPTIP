"""System-managed policy evaluation. This module grants no execution authority."""

from dataclasses import dataclass
from datetime import datetime, timezone
from hmac import compare_digest
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from .baseline_catalog import fingerprint


class ActivityDependency(BaseModel):
    model_config = ConfigDict(frozen=True, extra='forbid', strict=True)

    profile_id: str = Field(min_length=1)
    semantics: Literal['completed', 'ordering_only']


class PolicyRule(BaseModel):
    model_config = ConfigDict(frozen=True, extra='forbid', strict=True)

    rule_id: str = Field(min_length=1)
    activity: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    capability: str = Field(min_length=1)
    target_kind: Literal['IP address', 'Subnet', 'Hostname', 'Web URL']
    profile_id: str = Field(min_length=1)
    profile_version: int = Field(gt=0)
    disposition: Literal['preauthorized', 'requires_analyst_decision', 'blocked']
    parameter_digest: str = Field(pattern=r'^[0-9a-f]{64}$')
    risk: Literal['low', 'elevated', 'high']
    prerequisites: tuple[str, ...] = Field(min_length=1)
    max_units: int = Field(gt=0)
    stop_conditions: tuple[str, ...] = Field(min_length=1)
    activity_dependencies: tuple[ActivityDependency, ...] = ()

    @model_validator(mode='after')
    def validate_safety(self):
        if self.disposition == 'preauthorized' and self.risk != 'low':
            raise ValueError('Preauthorization requires explicit low-risk coverage.')
        for checks in (self.prerequisites, self.stop_conditions):
            if any(not check.strip() for check in checks) or len(checks) != len(set(checks)):
                raise ValueError('Safety check identifiers must be distinct and nonempty.')
        if len({dep.profile_id for dep in self.activity_dependencies}) != len(self.activity_dependencies):
            raise ValueError('Activity dependencies must identify distinct profiles.')
        return self


class PolicyDefinition(BaseModel):
    model_config = ConfigDict(frozen=True, extra='forbid', strict=True)

    policy_id: str = Field(min_length=1)
    version: int = Field(gt=0)
    rules: tuple[PolicyRule, ...] = Field(min_length=1)

    @model_validator(mode='after')
    def unique_rules(self):
        if len({rule.rule_id for rule in self.rules}) != len(self.rules):
            raise ValueError('Policy rule identifiers must be unique.')
        return self

    @property
    def digest(self):
        return fingerprint(self.model_dump(mode='json'))


class PolicyApproval(BaseModel):
    model_config = ConfigDict(frozen=True, extra='forbid', strict=True)

    policy_id: str = Field(min_length=1)
    version: int = Field(gt=0)
    digest: str = Field(pattern=r'^[0-9a-f]{64}$')
    provenance: str = Field(min_length=1, pattern=r'\S')
    reference: str | None = Field(default=None, min_length=1, pattern=r'\S')
    expires_at: datetime | None = None

    @model_validator(mode='after')
    def validate_expiry(self):
        if self.expires_at is not None and self.expires_at.utcoffset() is None:
            raise ValueError('Approval expiry must include a timezone.')
        return self


@dataclass(frozen=True)
class PolicySelection:
    status: str
    code: str
    message: str
    definition: PolicyDefinition | None = None
    approval: PolicyApproval | None = None

    def public_view(self):
        return {
            'status': self.status,
            'id': self.definition.policy_id if self.definition else None,
            'version': self.definition.version if self.definition else None,
            'digest': self.definition.digest if self.definition else None,
            'provenance': self.approval.provenance if self.approval else None,
            'reason': {'code': self.code, 'message': self.message},
        }


def select_policy(definition, trusted_approval):
    """Match the definition to an independently governed active approval record."""
    if definition is None:
        return PolicySelection('unavailable', 'execution_policy_missing', 'No approved execution policy is configured.')
    try:
        policy = PolicyDefinition.model_validate(definition)
        approval = PolicyApproval.model_validate(trusted_approval) if trusted_approval is not None else None
    except ValidationError:
        return PolicySelection('invalid', 'execution_policy_invalid', 'Execution policy or approval metadata is invalid.')
    if approval is None:
        return PolicySelection('unapproved', 'execution_policy_unapproved', 'Execution policy has no trusted approval.')
    if approval.expires_at is not None and approval.expires_at <= datetime.now(timezone.utc):
        return PolicySelection('stale', 'execution_policy_stale', 'Execution policy approval has expired.')
    if ((policy.policy_id, policy.version) != (approval.policy_id, approval.version)
            or not compare_digest(policy.digest, approval.digest)):
        return PolicySelection('stale', 'execution_policy_stale', 'Execution policy does not match the active approval.')
    return PolicySelection('approved', 'execution_policy_approved', 'Execution policy matches the active approval.',
                           policy, approval)


def effective_policy():
    # No operational definitions or approvals are shipped in B2.
    return select_policy(None, None)


@dataclass(frozen=True)
class ActivityContext:
    activity: str
    tool: str
    capability: str
    target_kind: str
    profile_id: str
    profile_version: int
    in_scope: bool
    baseline_current: bool
    tool_capable: bool
    parameter_digest: str | None = None
    risk: str | None = None
    verified_prerequisites: frozenset[str] = frozenset()
    requested_units: int | None = None
    clear_stop_conditions: frozenset[str] = frozenset()


def decision(code, message, rule=None, disposition='blocked'):
    return {'disposition': disposition, 'rule_id': rule.rule_id if rule else None,
            'reason_code': code, 'reason': message}


def evaluate_activity(selection, context):
    if selection.status != 'approved' or selection.definition is None:
        return decision(selection.code, selection.message)
    if not context.in_scope or not context.baseline_current or not context.tool_capable:
        return decision('activity_safety_gate_failed', 'Current scope, baseline, and tool capability are required.')

    identity = (context.activity, context.tool, context.capability, context.target_kind,
                context.profile_id, context.profile_version)
    matching = [rule for rule in selection.definition.rules
                if (rule.activity, rule.tool, rule.capability, rule.target_kind,
                    rule.profile_id, rule.profile_version) == identity]
    denial = min((rule for rule in matching if rule.disposition == 'blocked'),
                 key=lambda rule: rule.rule_id, default=None)
    if denial is not None:
        return decision('policy_explicit_denial', 'An approved policy rule blocks this activity.', denial)
    if not matching:
        return decision('policy_rule_missing', 'No approved rule covers this activity and profile.')
    if len(matching) != 1:
        return decision('policy_rule_ambiguous', 'Multiple policy rules match this activity and profile.')

    rule = matching[0]
    if context.parameter_digest != rule.parameter_digest:
        return decision('activity_parameters_unverified', 'Activity parameters do not match the approved envelope.', rule)
    if context.risk != rule.risk:
        return decision('activity_risk_unverified', 'Activity risk has not been verified against policy.', rule)
    if not set(rule.prerequisites) <= context.verified_prerequisites:
        return decision('activity_prerequisites_unverified', 'Required activity prerequisites are unverified.', rule)
    if (type(context.requested_units) is not int or not 0 < context.requested_units <= rule.max_units):
        return decision('activity_limit_unverified', 'Activity units are unverified or exceed the policy limit.', rule)
    if not set(rule.stop_conditions) <= context.clear_stop_conditions:
        return decision('activity_stop_conditions_unverified', 'Required stop conditions have not been cleared.', rule)
    return decision('policy_rule_matched', 'The activity satisfies the approved policy rule for review.',
                    rule, rule.disposition)
