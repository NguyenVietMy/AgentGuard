"""
Demo: Argument-level authorization on transfer_funds.

Same tool, different arguments, different outcomes.
This is the distinction that toolset selection cannot express.
"""

from agentguard import Guard, Policy, tool, value_lte

# --- Simulated tool ---

TOOL_REGISTRY: dict = {
    "transfer_funds": lambda **kwargs: f"Transferred ${kwargs['amount']} to {kwargs['account']}",
}

# --- Policy: transfer_funds allowed, but only up to $1,000 ---

policy = Policy(
    tools=[
        tool(
            "transfer_funds",
            allow=value_lte("amount", 1000),
        ),
    ],
)

guard = Guard(policy, on_deny="refuse")


@guard.protect
def dispatch(tool_name: str, args: dict) -> str:
    return TOOL_REGISTRY[tool_name](**args)


def main() -> None:
    print("=" * 60)
    print("AgentGuard Demo: Argument-Level Conditions")
    print("=" * 60)

    # Small transfer: allowed
    print("\n[Agent] Transfer $500 to ACC-123...")
    result = dispatch("transfer_funds", {"account": "ACC-123", "amount": 500})
    print(f"  Result: {result}")

    # Large transfer: denied
    print("\n[Agent] Transfer $50,000 to ACC-123...")
    result = dispatch("transfer_funds", {"account": "ACC-123", "amount": 50000})
    print(f"  Result: {result}")

    print("\n" + "-" * 60)
    print("Same tool. Different argument. Different outcome.")
    print("Toolset selection cannot express this distinction.")
    print("-" * 60)

    # --- Audit trail ---
    print("\n" + "=" * 60)
    print("Audit Trail")
    print("=" * 60)
    for entry in guard.audit_logger.entries:
        status = "ALLOWED" if entry.decision else "DENIED"
        print(f"  [{status}] {entry.tool}({entry.args})")
        print(f"           Reason: {entry.reason}")


if __name__ == "__main__":
    main()
