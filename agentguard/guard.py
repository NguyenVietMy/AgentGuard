from functools import wraps
from typing import Any, Callable, Literal, Optional

from agentguard.audit import AuditLogger
from agentguard.policy import Decision, Policy

OnDenyMode = Literal["refuse", "raise", "log_only"]
VALID_ON_DENY_MODES: set[str] = {"refuse", "raise", "log_only"}


class DeniedError(Exception):
    def __init__(self, decision: Decision) -> None:
        super().__init__(decision.reason)
        self.decision = decision


class Guard:
    def __init__(
        self,
        policy: Policy,
        on_deny: OnDenyMode = "refuse",
        audit_logger: Optional[AuditLogger] = None,
    ) -> None:
        if on_deny not in VALID_ON_DENY_MODES:
            valid_modes = ", ".join(sorted(VALID_ON_DENY_MODES))
            raise ValueError(f"Invalid on_deny mode {on_deny!r}. Expected one of: {valid_modes}")

        self.policy = policy
        self.on_deny = on_deny
        self.audit_logger: AuditLogger = audit_logger if audit_logger is not None else AuditLogger()

    def protect(self, func: Callable[[str, dict[str, Any]], Any]) -> Callable[[str, dict[str, Any]], Any]:
        @wraps(func)
        def wrapper(tool_name: str, args: dict[str, Any]) -> Any:
            decision = self.policy.check(tool_name, args)
            self.audit_logger.record(tool_name, args, decision)

            if decision.allowed:
                return func(tool_name, args)

            if self.on_deny == "refuse":
                return decision.denial_message
            elif self.on_deny == "raise":
                raise DeniedError(decision)
            elif self.on_deny == "log_only":
                return func(tool_name, args)

        return wrapper
