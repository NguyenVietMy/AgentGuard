# AgentGuard — Project Instructions

## What this is

A Python library that enforces deny-by-default, argument-level authorization on agent tool calls. Pure logic — no database, no network, no async required. Three modules: `policy.py`, `guard.py`, `audit.py`.

## Key architectural constraints

- **Pure library, no I/O in core:** `policy.py` and `guard.py` must remain pure, deterministic, no network/disk in the hot path. `audit.py` writes JSONL but that's the only I/O.
- **Fail closed, always:** A buggy condition, missing argument, or exception in a lambda must result in DENY. Never fail open.
- **Deny by default:** Unlisted tools are denied. No implicit allows.
- **No framework dependencies:** No LangChain, no LlamaIndex, no FastAPI. Zero required runtime dependencies beyond the Python stdlib. Keep `pyproject.toml` minimal.
- **Business logic lives in `policy.py`:** The `check()` method is the core — all authorization decisions happen there. `guard.py` is a thin integration wrapper.

## Code standards

- Type hints on all functions, class attributes, and return types
- Line length: 120 characters
- Indentation: 4 spaces
- Quotes: Double quotes for strings
- Trailing commas in multi-line structures
- All imports at the top of the file, three groups (stdlib, third-party, local), alphabetically sorted

## Import pattern

```python
# 1. Standard library
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Optional

# 2. Third-party (minimize — prefer none for core)

# 3. Local
from agentguard.policy import Policy
```

## Error handling

- Conditions that raise -> DENY (fail closed)
- Missing arguments that a condition references -> DENY (fail closed)
- Custom exceptions are fine but not required for MVP — the `Decision` object carries the reason string

## Testing

Exhaustive coverage on `policy.py` is non-negotiable — it's a security component. Key cases:
- Unlisted tool -> denied
- Allow condition true -> allowed; false -> denied
- Missing argument the condition references -> denied
- Condition that raises -> denied
- Audit log records both allowed and denied with correct reason

## Module layout

```
agentguard/
    __init__.py      # Public API re-exports: Policy, tool, Guard, Decision
    policy.py        # Policy, tool(), check() — the core, pure logic
    guard.py         # Guard, @protect decorator, on_deny modes
    audit.py         # Append-only JSONL audit log
demo/
    travel_agent.py  # Prompt injection containment demo
    transfer_funds.py # Argument-level condition demo
tests/
    test_policy.py
    test_guard.py
    test_audit.py
```

## Design decisions (MVP)

- **Conditions as lambdas** — simple and Pythonic. Not serializable, but that's a post-MVP concern.
- **`on_deny` modes:** `refuse` (return safe message), `raise` (hard fail), `log_only` (audit but allow — adoption on-ramp).
- **Audit format:** JSONL with `{timestamp, tool, args, decision, reason}`. In-memory list + optional file output.
- **No async:** The core is synchronous. Async wrappers are post-MVP.
