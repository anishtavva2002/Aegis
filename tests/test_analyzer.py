from aegis.analyzer import ScriptAnalyzer
from aegis.models import Decision

def test_safe_script_is_allowed():
    result = ScriptAnalyzer().analyze_text('print("hello")')
    assert result.decision == Decision.ALLOW
    assert result.risk_score == 0

def test_eval_requires_approval():
    result = ScriptAnalyzer().analyze_text('eval("1+1")')
    assert result.decision == Decision.APPROVAL_REQUIRED
    assert result.risk_score >= 35

def test_socket_is_denied():
    result = ScriptAnalyzer().analyze_text('import socket\nsocket.socket()')
    assert result.decision == Decision.DENY

def test_syntax_error_is_denied():
    result = ScriptAnalyzer().analyze_text('def broken(')
    assert result.decision == Decision.DENY
    assert result.risk_score == 100
