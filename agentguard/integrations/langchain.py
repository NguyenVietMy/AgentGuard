from typing import Any, Iterable, Optional

try:
    from langchain_core.tools import BaseTool
    from pydantic import PrivateAttr
except ImportError as exc:  # pragma: no cover - exercised only without optional deps installed
    raise ImportError(
        "The LangChain integration requires optional dependencies. "
        'Install them with: pip install "agentguard[langchain]"',
    ) from exc

from agentguard.audit import AuditLogger
from agentguard.guard import VALID_ON_DENY_MODES, DeniedError, OnDenyMode
from agentguard.policy import Decision, Policy


class GuardedLangChainTool(BaseTool):
    """LangChain BaseTool wrapper that enforces an AgentGuard policy before execution."""

    _tool: Any = PrivateAttr()
    _policy: Policy = PrivateAttr()
    _on_deny: OnDenyMode = PrivateAttr()
    _audit_logger: AuditLogger = PrivateAttr()

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

        tool_name = _require_tool_name(langchain_tool)
        super().__init__(
            name=tool_name,
            description=getattr(langchain_tool, "description", ""),
            args_schema=getattr(langchain_tool, "args_schema", None),
            return_direct=bool(getattr(langchain_tool, "return_direct", False)),
            tags=getattr(langchain_tool, "tags", None),
            metadata=getattr(langchain_tool, "metadata", None),
            response_format=getattr(langchain_tool, "response_format", "content"),
            extras=dict(getattr(langchain_tool, "extras", {}) or {}),
        )
        self._tool = langchain_tool
        self._policy = policy
        self._on_deny = on_deny
        self._audit_logger = audit_logger if audit_logger is not None else AuditLogger()

    @property
    def audit_logger(self) -> AuditLogger:
        return self._audit_logger

    @property
    def wrapped_tool(self) -> Any:
        return self._tool

    def _run(self, *args: Any, config: Any = None, **kwargs: Any) -> Any:
        tool_input = _parsed_tool_input(args, kwargs)
        decision = self._authorize(tool_input)

        if decision.allowed or self._on_deny == "log_only":
            return self._tool.invoke(tool_input, config=config)

        return self._handle_denied(decision)

    async def _arun(self, *args: Any, config: Any = None, **kwargs: Any) -> Any:
        tool_input = _parsed_tool_input(args, kwargs)
        decision = self._authorize(tool_input)

        if decision.allowed or self._on_deny == "log_only":
            return await self._tool.ainvoke(tool_input, config=config)

        return self._handle_denied(decision)

    def _authorize(self, input: Any) -> Decision:
        args = _tool_args(self._tool, input)
        decision = self._policy.check(self.name, args)
        self._audit_logger.record(self.name, args, decision)
        return decision

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


def _parsed_tool_input(args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
    if kwargs:
        return dict(kwargs)
    if len(args) == 1:
        return args[0]
    if args:
        return list(args)
    return {}


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
