import pytest

from agentguard.policy import Policy, tool


def make_policy() -> Policy:
    return Policy(
        tools=[
            tool("search_flights"),
            tool("send_email", allow=lambda args: args["to"].endswith("@mycompany.com")),
            tool("transfer_funds", allow=lambda args: args["amount"] <= 1000),
        ],
    )


# --- Deny by default ---


def test_unlisted_tool_is_denied():
    policy = make_policy()
    decision = policy.check("delete_user", {})
    assert decision.allowed is False


def test_deny_reason_contains_tool_name():
    policy = make_policy()
    decision = policy.check("delete_user", {})
    assert "delete_user" in decision.reason
    assert "deny by default" in decision.reason


def test_deny_message_is_not_empty():
    policy = make_policy()
    decision = policy.check("delete_user", {})
    assert decision.denial_message != ""


# --- Unconditional allow ---


def test_tool_with_no_condition_is_allowed():
    policy = make_policy()
    decision = policy.check("search_flights", {"from": "NYC", "to": "LAX"})
    assert decision.allowed is True


def test_unconditional_allow_reason_string():
    policy = make_policy()
    decision = policy.check("search_flights", {})
    assert "unconditionally" in decision.reason


def test_empty_args_with_unconditional_tool():
    policy = make_policy()
    decision = policy.check("search_flights", {})
    assert decision.allowed is True


# --- Condition-based allow ---


def test_condition_true_allows():
    policy = make_policy()
    decision = policy.check("send_email", {"to": "alice@mycompany.com", "body": "hello"})
    assert decision.allowed is True


def test_condition_false_denies():
    policy = make_policy()
    decision = policy.check("send_email", {"to": "attacker@evil.com", "body": "data"})
    assert decision.allowed is False


def test_condition_receives_full_args_dict():
    received_args = {}

    def capture_condition(args: dict) -> bool:
        received_args.update(args)
        return True

    policy = Policy(tools=[tool("mytool", allow=capture_condition)])
    policy.check("mytool", {"key1": "val1", "key2": "val2"})
    assert received_args == {"key1": "val1", "key2": "val2"}


def test_numeric_condition_allows():
    policy = make_policy()
    decision = policy.check("transfer_funds", {"account": "ACC123", "amount": 500})
    assert decision.allowed is True


def test_numeric_condition_denies():
    policy = make_policy()
    decision = policy.check("transfer_funds", {"account": "ACC123", "amount": 50000})
    assert decision.allowed is False


# --- Fail closed: missing argument ---


def test_missing_arg_key_access_is_denied():
    policy = make_policy()
    decision = policy.check("send_email", {"body": "no 'to' key"})
    assert decision.allowed is False


def test_denial_reason_contains_exception_type():
    policy = make_policy()
    decision = policy.check("send_email", {})
    assert "KeyError" in decision.reason


# --- Fail closed: condition raises ---


def test_condition_raising_value_error_is_denied():
    policy = Policy(tools=[tool("bad_tool", allow=lambda args: int("not_a_number"))])
    decision = policy.check("bad_tool", {})
    assert decision.allowed is False
    assert "ValueError" in decision.reason


def test_condition_raising_type_error_is_denied():
    policy = Policy(tools=[tool("bad_tool", allow=lambda args: len(None))])
    decision = policy.check("bad_tool", {})
    assert decision.allowed is False
    assert "TypeError" in decision.reason


def test_condition_raising_runtime_error_is_denied():
    def exploding_condition(args: dict) -> bool:
        raise RuntimeError("boom")

    policy = Policy(tools=[tool("bad_tool", allow=exploding_condition)])
    decision = policy.check("bad_tool", {})
    assert decision.allowed is False
    assert "RuntimeError" in decision.reason


# --- Decision fields ---


def test_allowed_decision_has_empty_denial_message():
    policy = make_policy()
    decision = policy.check("search_flights", {})
    assert decision.denial_message == ""


def test_denied_decision_has_non_empty_denial_message():
    policy = make_policy()
    decision = policy.check("delete_user", {})
    assert decision.denial_message != ""


def test_decision_allowed_is_bool():
    policy = make_policy()
    allowed = policy.check("search_flights", {})
    denied = policy.check("delete_user", {})
    assert type(allowed.allowed) is bool
    assert type(denied.allowed) is bool


# --- Multiple tools ---


def test_second_tool_allowed_first_denied():
    policy = make_policy()
    denied = policy.check("send_email", {"to": "attacker@evil.com", "body": ""})
    allowed = policy.check("search_flights", {})
    assert denied.allowed is False
    assert allowed.allowed is True


def test_tool_index_is_case_sensitive():
    policy = make_policy()
    decision = policy.check("Search_Flights", {})
    assert decision.allowed is False


# --- Edge cases ---


def test_condition_returning_truthy_nonbool_is_allowed():
    policy = Policy(tools=[tool("truthy_tool", allow=lambda args: 1)])
    decision = policy.check("truthy_tool", {})
    assert decision.allowed is True


def test_condition_returning_falsy_nonbool_is_denied():
    policy = Policy(tools=[tool("falsy_tool", allow=lambda args: 0)])
    decision = policy.check("falsy_tool", {})
    assert decision.allowed is False


def test_empty_policy_denies_everything():
    policy = Policy(tools=[])
    decision = policy.check("anything", {})
    assert decision.allowed is False


def test_duplicate_tool_names_raise_value_error():
    with pytest.raises(ValueError, match="Duplicate tool names"):
        Policy(tools=[tool("send_email"), tool("send_email")])


def test_decision_includes_tool_name_and_reason_code():
    policy = make_policy()
    decision = policy.check("delete_user", {})
    assert decision.tool_name == "delete_user"
    assert decision.reason_code == "tool_not_listed"
