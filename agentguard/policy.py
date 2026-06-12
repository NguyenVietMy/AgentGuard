from dataclasses import dataclass, field
from typing import Any, Callable, Literal, Optional

ReasonCode = Literal[
    "allowed_unconditional",
    "allowed_condition",
    "condition_failed",
    "condition_error",
    "duplicate_tool",
    "tool_not_listed",
]


@dataclass
class Decision:
    allowed: bool
    reason: str
    denial_message: str
    tool_name: str = ""
    reason_code: ReasonCode = "condition_failed"


@dataclass
class ToolSpec:
    name: str
    allow: Optional[Callable[[dict[str, Any]], bool]] = field(default=None)


def tool(name: str, allow: Optional[Callable[[dict[str, Any]], bool]] = None) -> ToolSpec:
    return ToolSpec(name=name, allow=allow)


@dataclass
class Policy:
    tools: list[ToolSpec]

    def __post_init__(self) -> None:
        names: set[str] = set()
        duplicates: set[str] = set()

        for spec in self.tools:
            if spec.name in names:
                duplicates.add(spec.name)
            names.add(spec.name)

        if duplicates:
            duplicate_list = ", ".join(sorted(duplicates))
            raise ValueError(f"Duplicate tool names in policy: {duplicate_list}")

        self._tool_index: dict[str, ToolSpec] = {t.name: t for t in self.tools}

    def check(self, tool_name: str, args: dict[str, Any]) -> Decision:
        if tool_name not in self._tool_index:
            return Decision(
                allowed=False,
                reason=f"{tool_name} is not in the policy (deny by default)",
                denial_message=f"Action {tool_name!r} is not permitted.",
                tool_name=tool_name,
                reason_code="tool_not_listed",
            )

        spec = self._tool_index[tool_name]

        if spec.allow is None:
            return Decision(
                allowed=True,
                reason=f"{tool_name} allowed unconditionally",
                denial_message="",
                tool_name=tool_name,
                reason_code="allowed_unconditional",
            )

        try:
            result = spec.allow(args)
        except Exception as exc:
            return Decision(
                allowed=False,
                reason=f"{tool_name} denied: allow condition raised {type(exc).__name__}: {exc}",
                denial_message=f"Action {tool_name!r} is not permitted.",
                tool_name=tool_name,
                reason_code="condition_error",
            )

        if result:
            return Decision(
                allowed=True,
                reason=f"{tool_name} allowed: allow condition passed",
                denial_message="",
                tool_name=tool_name,
                reason_code="allowed_condition",
            )

        return Decision(
            allowed=False,
            reason=f"{tool_name} denied: allow condition returned False",
            denial_message=f"Action {tool_name!r} is not permitted.",
            tool_name=tool_name,
            reason_code="condition_failed",
        )
