# AgentGuard

Deny-by-default, argument-level authorization for AI agent tool calls.

Tool access is binary; real authorization is conditional. AgentGuard sits between an LLM's tool-call output
and actual tool execution, enforcing fine-grained policies that toolset selection cannot express.

AgentGuard is not a prompt-injection detector. It assumes the model can be tricked and limits what the
tricked model is allowed to do.

## Install

```bash
pip install agentguard
```

## Quick Start

```python
from agentguard import Guard, Policy, email_domain, tool, value_lte

TOOL_REGISTRY = {
    "send_email": lambda **args: f"sent email to {args['to']}",
    "transfer_funds": lambda **args: f"transferred ${args['amount']}",
}

policy = Policy(
    tools=[
        tool("send_email", allow=email_domain("to", ["mycompany.com"])),
        tool("transfer_funds", allow=value_lte("amount", 1000)),
    ],
)

guard = Guard(policy, on_deny="refuse")


@guard.protect
def dispatch(tool_name: str, args: dict) -> str:
    return TOOL_REGISTRY[tool_name](**args)


dispatch("send_email", {"to": "alice@mycompany.com"})
# "sent email to alice@mycompany.com"

dispatch("send_email", {"to": "attacker@evil.com"})
# "Action 'send_email' is not permitted."

dispatch("delete_user", {"user_id": "123"})
# "Action 'delete_user' is not permitted."
```

Only tools listed in the policy are eligible to run. Unlisted tools are denied by default.

## Policy Presets

AgentGuard supports plain Python lambdas, but common policies should be easy to read and reuse:

```python
from agentguard import (
    Policy,
    email_domain,
    path_under,
    shell_command_allowlist,
    sql_readonly,
    tool,
    url_host_in,
    value_lte,
)

policy = Policy(
    tools=[
        tool("send_email", allow=email_domain("to", ["mycompany.com"])),
        tool("transfer_funds", allow=value_lte("amount", 1000)),
        tool("run_sql", allow=sql_readonly("query")),
        tool("write_file", allow=path_under("path", "./workspace")),
        tool("fetch_url", allow=url_host_in("url", ["api.mycompany.com"])),
        tool("run_command", allow=shell_command_allowlist("command", ["git status", "uv run pytest"])),
    ],
)
```

Available presets:

- `email_domain(arg, domains)`
- `value_lte(arg, max_value)`
- `value_in(arg, allowed_values)`
- `path_under(arg, root)`
- `url_host_in(arg, hosts)`
- `sql_readonly(arg="query")`
- `shell_command_allowlist(arg="command", prefixes=[...])`
- `all_of(...)`, `any_of(...)`, `not_(...)`

Conditions fail closed. Missing arguments, bad types, or exceptions result in denial.

## Audit Log

Every guarded call is recorded in memory. You can also write JSONL:

```python
from agentguard import AuditLogger, Guard


def redact(args: dict) -> dict:
    return {**args, "body": "[REDACTED]"} if "body" in args else args


audit = AuditLogger(filepath="audit.jsonl", redact=redact)
guard = Guard(policy, on_deny="refuse", audit_logger=audit)
```

Audit entries include a schema version, timestamp, tool name, redacted args, boolean decision,
human-readable decision text, reason code, and reason.

## Deny Modes

```python
Guard(policy, on_deny="refuse")   # return a safe denial message
Guard(policy, on_deny="raise")    # raise DeniedError
Guard(policy, on_deny="log_only") # record the denial but still execute
```

Use `log_only` to observe what would be denied before enforcing a policy.

## Demos

Run the included demos:

```bash
uv run python demo/travel_agent.py
uv run python demo/transfer_funds.py
uv run pytest
```

The travel demo shows prompt-injection containment: the model-level attack succeeds, but the unsafe
`send_email` tool call is denied because the recipient is outside the allowed domain.

The transfer demo shows the core argument-level point: the same `transfer_funds` tool is allowed for
`amount=500` and denied for `amount=50000`.

## Why Not Just Pass The Allowed Tools?

Passing a list of tools gives binary access control: a tool is either available or it is not. Real
authorization is conditional:

- The agent can send email, but only to internal addresses.
- The agent can transfer funds, but only up to $1,000.
- The agent can write files, but only inside a workspace directory.
- The agent can query SQL, but only with read-only statements.

These are the same tools with different arguments. Toolset selection cannot express that distinction.

## How Is This Different From Text Guardrails?

Tools such as prompt-injection scanners, PII detectors, and output guardrails inspect text. That is
detection.

AgentGuard authorizes actions: "Is this exact tool call permitted under this policy?" That is enforcement.
The layers are complementary.

## Project Direction

AgentGuard is intentionally small at the core. The next adoption-focused milestones are:

1. Framework adapters for LangChain/LangGraph and the OpenAI Agents SDK.
2. More presets for common risky tools.
3. CLI helpers for checking policy decisions and inspecting audit logs.
4. MCP proxy experiments for framework-independent tool authorization.

## Limitations

- Authorization is one layer; pair it with input scanning and good tool design.
- AgentGuard cannot decide your policy for you. You must know what actions your agent should be allowed to take.
- The current package protects Python dispatch paths. Framework-specific integrations are planned.
- Keep high-risk tools narrow. A policy layer is not a substitute for safe underlying tool implementations.
