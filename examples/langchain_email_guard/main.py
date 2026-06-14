from langchain.tools import tool as langchain_tool

from agentguard import Policy, email_domain, tool
from agentguard.integrations.langchain import guard_tools


@langchain_tool
def send_email(to: str, body: str) -> str:
    """Send an email."""
    return f"sent email to {to}: {body}"


policy = Policy(
    tools=[
        tool("send_email", allow=email_domain("to", ["mycompany.com"])),
    ],
)

safe_tools = guard_tools([send_email], policy, on_deny="refuse")
safe_send_email = safe_tools[0]

print(safe_send_email.invoke({"to": "alice@mycompany.com", "body": "Booking confirmed."}))
print(safe_send_email.invoke({"to": "attacker@evil.com", "body": "Customer export."}))

for entry in safe_send_email.audit_logger.entries:
    print(f"{entry.decision_text.upper()} {entry.tool}: {entry.reason}")
