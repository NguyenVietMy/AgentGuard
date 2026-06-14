# Contributing

Thanks for helping improve AgentGuard.

AgentGuard is intentionally small: the core package should stay dependency-free, synchronous, and focused on
deny-by-default authorization for tool calls. Integrations may add optional dependencies, but importing
`agentguard` itself should require only the Python standard library.

## Development Setup

```bash
uv sync --extra dev --extra langchain
uv run --extra dev --extra langchain pytest
uv run --extra dev --extra langchain ruff check .
```

## Project Rules

- Keep `agentguard.policy` and `agentguard.guard` pure and deterministic.
- Fail closed. Missing arguments, bad condition code, or unexpected errors in policy checks must deny.
- Add tests for authorization behavior, especially deny paths.
- Keep runtime dependencies out of the core package.
- Prefer focused changes over broad refactors.

## Pull Requests

Before opening a PR:

```bash
uv run --extra dev --extra langchain pytest
uv run --extra dev --extra langchain ruff check .
```

In the PR description, include:

- what changed
- why it matters
- tests run
- any compatibility concerns

## Security Issues

If you find a behavior that can fail open or bypass policy enforcement, please open an issue with a minimal
reproduction. Avoid posting real secrets, credentials, or production audit logs.
