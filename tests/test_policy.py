import pytest
from aegis.policy import PolicyEngine
from aegis.models import Decision

def test_policy_requires_approval_at_threshold():
    policy = PolicyEngine()
    assert policy.decide(35, Decision.ALLOW) == Decision.APPROVAL_REQUIRED

def test_policy_denies_at_threshold():
    policy = PolicyEngine()
    assert policy.decide(80, Decision.ALLOW) == Decision.DENY

def test_network_cannot_be_enabled_in_v1(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text('{"network_disabled": false}')
    with pytest.raises(ValueError):
        PolicyEngine(path)
