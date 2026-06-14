import asyncio
from typing import Any

import pytest

from agentguard import AuditLogger, Policy, email_domain, tool
from agentguard.guard import DeniedError
from agentguard.integrations.langchain import guard_tool, guard_tools


class FakeLangChainTool:
    name = "send_email"
    description = "Send an email."
    args_schema = object()
    return_direct = False
    response_format = "content"
    extras = {"example": True}
    args = {"to": {"type": "string"}}

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def invoke(self, input: Any, config: Any = None, **kwargs: Any) -> str:
        self.calls.append({"input": input, "config": config, "kwargs": kwargs})
        return f"sent:{input['to']}"

    async def ainvoke(self, input: Any, config: Any = None, **kwargs: Any) -> str:
        self.calls.append({"input": input, "config": config, "kwargs": kwargs})
        return f"sent:{input['to']}"

    def get_input_schema(self, config: Any = None) -> object:
        return self.args_schema

    def get_output_schema(self, config: Any = None) -> str:
        return "output-schema"


class FakeStringTool:
    name = "search"
    description = "Search."
    args = {"query": {"type": "string"}}

    def __init__(self) -> None:
        self.calls: list[Any] = []

    def invoke(self, input: Any, config: Any = None, **kwargs: Any) -> str:
        self.calls.append(input)
        return f"searched:{input}"


def _policy() -> Policy:
    return Policy(
        tools=[
            tool("send_email", allow=email_domain("to", ["mycompany.com"])),
            tool("search"),
        ],
    )


def test_guard_tool_preserves_langchain_tool_metadata():
    original = FakeLangChainTool()
    guarded = guard_tool(original, _policy())
    assert guarded.name == original.name
    assert guarded.description == original.description
    assert guarded.args_schema is original.args_schema
    assert guarded.response_format == original.response_format
    assert guarded.extras == original.extras


def test_guard_tool_allows_policy_approved_call():
    original = FakeLangChainTool()
    guarded = guard_tool(original, _policy())
    result = guarded.invoke({"to": "alice@mycompany.com"})
    assert result == "sent:alice@mycompany.com"
    assert len(original.calls) == 1
    assert guarded.audit_logger.entries[0].decision is True


def test_guard_tool_raise_mode_blocks_denied_call():
    original = FakeLangChainTool()
    guarded = guard_tool(original, _policy(), on_deny="raise")
    with pytest.raises(DeniedError):
        guarded.invoke({"to": "attacker@evil.com"})
    assert original.calls == []
    assert guarded.audit_logger.entries[0].decision is False


def test_guard_tool_refuse_mode_returns_denial_message():
    original = FakeLangChainTool()
    guarded = guard_tool(original, _policy(), on_deny="refuse")
    result = guarded.invoke({"to": "attacker@evil.com"})
    assert result == "Action 'send_email' is not permitted."
    assert original.calls == []


def test_guard_tool_log_only_executes_denied_call():
    original = FakeLangChainTool()
    guarded = guard_tool(original, _policy(), on_deny="log_only")
    result = guarded.invoke({"to": "attacker@evil.com"})
    assert result == "sent:attacker@evil.com"
    assert len(original.calls) == 1
    assert guarded.audit_logger.entries[0].decision is False


def test_guard_tool_extracts_args_from_langchain_tool_call_dict():
    original = FakeLangChainTool()
    guarded = guard_tool(original, _policy(), on_deny="refuse")
    result = guarded.invoke({"name": "send_email", "args": {"to": "attacker@evil.com"}, "id": "call_1"})
    assert result == "Action 'send_email' is not permitted."
    assert original.calls == []


def test_guard_tool_maps_string_input_to_single_tool_arg():
    original = FakeStringTool()
    guarded = guard_tool(original, _policy())
    result = guarded.invoke("flights to LAX")
    assert result == "searched:flights to LAX"
    assert guarded.audit_logger.entries[0].args == {"query": "flights to LAX"}


def test_guard_tool_forwards_config_and_kwargs_to_original_tool():
    original = FakeLangChainTool()
    guarded = guard_tool(original, _policy())
    guarded.invoke({"to": "alice@mycompany.com"}, config={"tags": ["test"]}, run_name="email")
    assert original.calls[0]["config"] == {"tags": ["test"]}
    assert original.calls[0]["kwargs"] == {"run_name": "email"}


def test_guard_tool_async_invoke_applies_policy():
    original = FakeLangChainTool()
    guarded = guard_tool(original, _policy())
    result = asyncio.run(guarded.ainvoke({"to": "alice@mycompany.com"}))
    assert result == "sent:alice@mycompany.com"
    assert guarded.audit_logger.entries[0].decision is True


def test_guard_tools_share_audit_logger():
    logger = AuditLogger()
    guarded_tools = guard_tools([FakeLangChainTool(), FakeStringTool()], _policy(), audit_logger=logger)
    guarded_tools[0].invoke({"to": "alice@mycompany.com"})
    guarded_tools[1].invoke("hotels")
    assert len(logger.entries) == 2


def test_guard_tool_rejects_tool_without_name():
    class NamelessTool:
        name = ""

    with pytest.raises(ValueError, match="non-empty string name"):
        guard_tool(NamelessTool(), _policy())
