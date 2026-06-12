import pytest

from agentguard.audit import AuditLogger
from agentguard.guard import DeniedError, Guard
from agentguard.policy import Policy, tool


def _make_guard(on_deny: str = "refuse", audit_logger: AuditLogger | None = None) -> Guard:
    policy = Policy(
        tools=[
            tool("allowed_tool"),
            tool("conditional_tool", allow=lambda args: args["ok"]),
        ],
    )
    return Guard(policy, on_deny=on_deny, audit_logger=audit_logger)


def _dispatch(tool_name: str, args: dict) -> str:
    """Test dispatcher."""
    return f"executed:{tool_name}"


# --- protect: allowed calls ---


def test_protect_allows_and_calls_func():
    guard = _make_guard()
    protected = guard.protect(_dispatch)
    result = protected("allowed_tool", {})
    assert result == "executed:allowed_tool"


def test_protect_allows_conditional_when_condition_passes():
    guard = _make_guard()
    protected = guard.protect(_dispatch)
    result = protected("conditional_tool", {"ok": True})
    assert result == "executed:conditional_tool"


# --- protect: refuse mode ---


def test_protect_refuse_mode_returns_denial_message():
    guard = _make_guard(on_deny="refuse")
    protected = guard.protect(_dispatch)
    result = protected("conditional_tool", {"ok": False})
    assert "not permitted" in result


def test_protect_refuse_mode_does_not_call_func():
    called = []

    def tracking_dispatch(tool_name: str, args: dict) -> str:
        called.append(tool_name)
        return "executed"

    guard = _make_guard(on_deny="refuse")
    protected = guard.protect(tracking_dispatch)
    protected("conditional_tool", {"ok": False})
    assert called == []


# --- protect: raise mode ---


def test_protect_raise_mode_raises_denied_error():
    guard = _make_guard(on_deny="raise")
    protected = guard.protect(_dispatch)
    with pytest.raises(DeniedError):
        protected("conditional_tool", {"ok": False})


def test_denied_error_carries_decision():
    guard = _make_guard(on_deny="raise")
    protected = guard.protect(_dispatch)
    with pytest.raises(DeniedError) as exc_info:
        protected("conditional_tool", {"ok": False})
    assert exc_info.value.decision.allowed is False
    assert "conditional_tool" in exc_info.value.decision.reason


# --- protect: log_only mode ---


def test_protect_log_only_mode_calls_func_even_when_denied():
    guard = _make_guard(on_deny="log_only")
    protected = guard.protect(_dispatch)
    result = protected("conditional_tool", {"ok": False})
    assert result == "executed:conditional_tool"


def test_protect_log_only_still_records_to_audit():
    guard = _make_guard(on_deny="log_only")
    protected = guard.protect(_dispatch)
    protected("conditional_tool", {"ok": False})
    entries = guard.audit_logger.entries
    assert len(entries) == 1
    assert entries[0].decision is False


# --- audit integration ---


def test_guard_creates_audit_logger_if_not_provided():
    guard = _make_guard()
    assert guard.audit_logger is not None


def test_guard_uses_provided_audit_logger():
    logger = AuditLogger()
    guard = _make_guard(audit_logger=logger)
    assert guard.audit_logger is logger


def test_audit_records_allowed_calls():
    guard = _make_guard()
    protected = guard.protect(_dispatch)
    protected("allowed_tool", {})
    entries = guard.audit_logger.entries
    assert len(entries) == 1
    assert entries[0].decision is True


def test_audit_records_denied_calls():
    guard = _make_guard(on_deny="refuse")
    protected = guard.protect(_dispatch)
    protected("conditional_tool", {"ok": False})
    entries = guard.audit_logger.entries
    assert len(entries) == 1
    assert entries[0].decision is False


def test_all_three_modes_record_to_audit():
    for mode in ("refuse", "raise", "log_only"):
        guard = _make_guard(on_deny=mode)
        protected = guard.protect(_dispatch)
        try:
            protected("conditional_tool", {"ok": False})
        except DeniedError:
            pass
        assert len(guard.audit_logger.entries) == 1, f"mode={mode} failed to record"


def test_unlisted_tool_denied_via_guard():
    guard = _make_guard(on_deny="refuse")
    protected = guard.protect(_dispatch)
    result = protected("delete_user", {})
    assert "not permitted" in result
    assert guard.audit_logger.entries[0].decision is False


def test_invalid_on_deny_mode_raises_value_error():
    with pytest.raises(ValueError, match="Invalid on_deny mode"):
        _make_guard(on_deny="unknown")


def test_protect_preserves_wrapped_function_metadata():
    guard = _make_guard()
    protected = guard.protect(_dispatch)
    assert protected.__name__ == "_dispatch"
    assert protected.__doc__ == "Test dispatcher."
