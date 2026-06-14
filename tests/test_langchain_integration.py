import asyncio

import pytest

pytest.importorskip("langchain")
pytest.importorskip("langchain_core")

from langchain.tools import tool as langchain_tool  # noqa: E402
from langchain_core.tools import BaseTool, StructuredTool  # noqa: E402

from agentguard import AuditLogger, Policy, email_domain, tool
from agentguard.guard import DeniedError
from agentguard.integrations.langchain import guard_tool, guard_tools

CALLS: list[dict[str, str]] = []


@langchain_tool
def send_email(to: str, body: str) -> str:
    """Send an email."""
    CALLS.append({"to": to, "body": body})
    return f"sent:{to}:{body}"


@langchain_tool
def search(query: str) -> str:
    """Search for information."""
    CALLS.append({"query": query})
    return f"searched:{query}"


def transfer_funds(account: str, amount: int) -> str:
    """Transfer funds."""
    CALLS.append({"account": account, "amount": str(amount)})
    return f"transferred:{amount}:{account}"


async def async_send_email(to: str, body: str) -> str:
    """Send an email asynchronously."""
    CALLS.append({"to": to, "body": body})
    return f"async-sent:{to}:{body}"


@pytest.fixture(autouse=True)
def clear_calls() -> None:
    CALLS.clear()


def _policy() -> Policy:
    return Policy(
        tools=[
            tool("send_email", allow=email_domain("to", ["mycompany.com"])),
            tool("search"),
            tool("transfer_funds", allow=lambda args: args["amount"] <= 1000),
            tool("async_send_email", allow=email_domain("to", ["mycompany.com"])),
        ],
    )


def test_guard_tool_returns_langchain_base_tool():
    guarded = guard_tool(send_email, _policy())
    assert isinstance(guarded, BaseTool)


def test_guard_tool_preserves_tool_metadata():
    guarded = guard_tool(send_email, _policy())
    assert guarded.name == send_email.name
    assert guarded.description == send_email.description
    assert guarded.args_schema is send_email.args_schema
    assert guarded.return_direct == send_email.return_direct
    assert guarded.response_format == send_email.response_format


def test_guard_tool_allows_policy_approved_call():
    guarded = guard_tool(send_email, _policy())
    result = guarded.invoke({"to": "alice@mycompany.com", "body": "hello"})
    assert result == "sent:alice@mycompany.com:hello"
    assert CALLS == [{"to": "alice@mycompany.com", "body": "hello"}]
    assert guarded.audit_logger.entries[0].decision is True


def test_guard_tool_raise_mode_blocks_denied_call():
    guarded = guard_tool(send_email, _policy(), on_deny="raise")
    with pytest.raises(DeniedError):
        guarded.invoke({"to": "attacker@evil.com", "body": "customer export"})
    assert CALLS == []
    assert guarded.audit_logger.entries[0].decision is False


def test_guard_tool_refuse_mode_returns_denial_message():
    guarded = guard_tool(send_email, _policy(), on_deny="refuse")
    result = guarded.invoke({"to": "attacker@evil.com", "body": "customer export"})
    assert result == "Action 'send_email' is not permitted."
    assert CALLS == []


def test_guard_tool_log_only_executes_denied_call():
    guarded = guard_tool(send_email, _policy(), on_deny="log_only")
    result = guarded.invoke({"to": "attacker@evil.com", "body": "customer export"})
    assert result == "sent:attacker@evil.com:customer export"
    assert CALLS == [{"to": "attacker@evil.com", "body": "customer export"}]
    assert guarded.audit_logger.entries[0].decision is False


def test_guard_tool_allows_tool_call_shaped_input_and_preserves_response_shape():
    guarded = guard_tool(send_email, _policy())
    result = guarded.invoke(
        {
            "name": "send_email",
            "args": {"to": "alice@mycompany.com", "body": "hello"},
            "id": "call_1",
            "type": "tool_call",
        },
    )
    assert result.content == "sent:alice@mycompany.com:hello"
    assert result.name == "send_email"
    assert result.tool_call_id == "call_1"
    assert guarded.audit_logger.entries[0].args == {"to": "alice@mycompany.com", "body": "hello"}


def test_guard_tool_denies_tool_call_shaped_input_before_execution():
    guarded = guard_tool(send_email, _policy(), on_deny="refuse")
    result = guarded.invoke(
        {
            "name": "send_email",
            "args": {"to": "attacker@evil.com", "body": "customer export"},
            "id": "call_1",
            "type": "tool_call",
        },
    )
    assert result.content == "Action 'send_email' is not permitted."
    assert result.name == "send_email"
    assert result.tool_call_id == "call_1"
    assert CALLS == []


def test_guard_tool_maps_string_input_to_single_tool_arg():
    guarded = guard_tool(search, _policy())
    result = guarded.invoke("flights to LAX")
    assert result == "searched:flights to LAX"
    assert guarded.audit_logger.entries[0].args == {"query": "flights to LAX"}


def test_guard_tool_wraps_structured_tool_from_function():
    structured = StructuredTool.from_function(transfer_funds)
    guarded = guard_tool(structured, _policy(), on_deny="refuse")
    allowed = guarded.invoke({"account": "ACC-123", "amount": 500})
    denied = guarded.invoke({"account": "ACC-123", "amount": 50000})
    assert allowed == "transferred:500:ACC-123"
    assert denied == "Action 'transfer_funds' is not permitted."
    assert CALLS == [{"account": "ACC-123", "amount": "500"}]


def test_guard_tool_async_invoke_applies_policy_to_sync_tool():
    guarded = guard_tool(send_email, _policy())
    result = asyncio.run(guarded.ainvoke({"to": "alice@mycompany.com", "body": "hello"}))
    assert result == "sent:alice@mycompany.com:hello"
    assert guarded.audit_logger.entries[0].decision is True


def test_guard_tool_async_invoke_applies_policy_to_async_tool():
    async_tool = StructuredTool.from_function(coroutine=async_send_email)
    guarded = guard_tool(async_tool, _policy())
    result = asyncio.run(guarded.ainvoke({"to": "alice@mycompany.com", "body": "hello"}))
    assert result == "async-sent:alice@mycompany.com:hello"
    assert guarded.audit_logger.entries[0].decision is True


def test_guard_tool_sync_invoke_preserves_async_only_tool_failure_when_allowed():
    async_tool = StructuredTool.from_function(coroutine=async_send_email)
    guarded = guard_tool(async_tool, _policy())
    with pytest.raises(NotImplementedError, match="does not support sync invocation"):
        guarded.invoke({"to": "alice@mycompany.com", "body": "hello"})
    assert guarded.audit_logger.entries[0].decision is True


def test_guard_tools_share_audit_logger():
    logger = AuditLogger()
    guarded_tools = guard_tools([send_email, search], _policy(), audit_logger=logger)
    guarded_tools[0].invoke({"to": "alice@mycompany.com", "body": "hello"})
    guarded_tools[1].invoke("hotels")
    assert len(logger.entries) == 2


def test_guard_tool_rejects_tool_without_name():
    class NamelessTool:
        name = ""

    with pytest.raises(ValueError, match="non-empty string name"):
        guard_tool(NamelessTool(), _policy())


def test_invalid_on_deny_mode_raises_value_error():
    with pytest.raises(ValueError, match="Invalid on_deny mode"):
        guard_tool(send_email, _policy(), on_deny="unknown")
