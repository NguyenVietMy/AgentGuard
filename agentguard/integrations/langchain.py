from typing import Any, Iterable, Optional

from agentguard.audit import AuditLogger
from agentguard.guard import VALID_ON_DENY_MODES, DeniedError, OnDenyMode
from agentguard.policy import Decision, Policy


class GuardedLangChainTool:
    """Wrap a LangChain-style tool with AgentGuard authorization."""

    def __init__(
        self,
        langchain_tool: Any,
        policy: Policy,
        on_deny: OnDenyMode = "raise",
        audit_logger: Optional[AuditLogger] = None,
    ) -> None:
        if on_deny not in VALID_ON_DENY_MODES:
            valid_modes = ", ".join(sorted(VALID_ON_DENY_MODES))
            raise ValueError(f"Invalid on_deny mode {on_deny!r}. Expected one of: {valid_modes}")

        self._tool = langchain_tool
        self._policy = policy
        self._on_deny = on_deny
        self._audit_logger = audit_logger if audit_logger is not None else AuditLogger()

        self.name: str = _require_tool_name(langchain_tool)
        self.description: str = getattr(langchain_tool, "description", "")
        self.args_schema: Any = getattr(langchain_tool, "args_schema", None)
        self.return_direct: bool = bool(getattr(langchain_tool, "return_direct", False))
        self.response_format: str = getattr(langchain_tool, "response_format", "content")
        self.extras: dict[str, Any] = dict(getattr(langchain_tool, "extras", {}) or {})

    @property
    def audit_logger(self) -> AuditLogger:
        return self._audit_logger

    @property
    def wrapped_tool(self) -> Any:
        return self._tool

    def invoke(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        args = _tool_args(self._tool, input)
        decision = self._policy.check(self.name, args)
        self._audit_logger.record(self.name, args, decision)

        if decision.allowed or self._on_deny == "log_only":
            return self._tool.invoke(input, config=config, **kwargs)

        return self._handle_denied(decision)

    async def ainvoke(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        args = _tool_args(self._tool, input)
        decision = self._policy.check(self.name, args)
        self._audit_logger.record(self.name, args, decision)

        if decision.allowed or self._on_deny == "log_only":
            return await self._tool.ainvoke(input, config=config, **kwargs)

        return self._handle_denied(decision)

    def get_input_schema(self, config: Any = None) -> Any:
        if hasattr(self._tool, "get_input_schema"):
            return self._tool.get_input_schema(config=config)
        return self.args_schema

    def get_output_schema(self, config: Any = None) -> Any:
        if hasattr(self._tool, "get_output_schema"):
            return self._tool.get_output_schema(config=config)
        return None

    def __getattr__(self, name: str) -> Any:
        return getattr(self._tool, name)

    def _handle_denied(self, decision: Decision) -> str:
        if self._on_deny == "refuse":
            return decision.denial_message
        raise DeniedError(decision)


def guard_tool(
    langchain_tool: Any,
    policy: Policy,
    on_deny: OnDenyMode = "raise",
    audit_logger: Optional[AuditLogger] = None,
) -> GuardedLangChainTool:
    return GuardedLangChainTool(
        langchain_tool=langchain_tool,
        policy=policy,
        on_deny=on_deny,
        audit_logger=audit_logger,
    )


def guard_tools(
    tools: Iterable[Any],
    policy: Policy,
    on_deny: OnDenyMode = "raise",
    audit_logger: Optional[AuditLogger] = None,
) -> list[GuardedLangChainTool]:
    shared_logger = audit_logger if audit_logger is not None else AuditLogger()
    return [
        guard_tool(
            langchain_tool=langchain_tool,
            policy=policy,
            on_deny=on_deny,
            audit_logger=shared_logger,
        )
        for langchain_tool in tools
    ]


def _require_tool_name(langchain_tool: Any) -> str:
    name = getattr(langchain_tool, "name", "")
    if not isinstance(name, str) or not name:
        raise ValueError("LangChain tool must expose a non-empty string name")
    return name


def _tool_args(langchain_tool: Any, input: Any) -> dict[str, Any]:
    if isinstance(input, dict):
        nested_args = input.get("args")
        if isinstance(nested_args, dict) and "name" in input:
            return dict(nested_args)
        return dict(input)

    input_key = _single_input_key(langchain_tool)
    return {input_key: input}


def _single_input_key(langchain_tool: Any) -> str:
    args = getattr(langchain_tool, "args", None)
    if isinstance(args, dict) and len(args) == 1:
        return next(iter(args))
    return "input"
