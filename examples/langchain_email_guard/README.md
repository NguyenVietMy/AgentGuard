# LangChain Email Guard Example

This example shows the intended integration shape for LangChain tools:

```python
from agentguard import Policy, email_domain, tool
from agentguard.integrations.langchain import guard_tools

policy = Policy([
    tool("send_email", allow=email_domain("to", ["mycompany.com"])),
])

safe_tools = guard_tools([send_email], policy, on_deny="refuse")
```

Install the optional integration dependencies first:

```bash
pip install "agentguard[langchain]"
```

Then run:

```bash
python examples/langchain_email_guard/main.py
```
