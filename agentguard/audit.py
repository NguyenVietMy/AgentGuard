import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from agentguard.policy import Decision

SCHEMA_VERSION = "1.0"
AuditRedactor = Callable[[dict[str, Any]], dict[str, Any]]


@dataclass
class AuditEntry:
    timestamp: str
    tool: str
    args: dict[str, Any]
    decision: bool
    reason: str
    schema_version: str = SCHEMA_VERSION
    reason_code: str = ""
    decision_text: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "timestamp": self.timestamp,
            "tool": self.tool,
            "args": self.args,
            "decision": self.decision,
            "decision_text": self.decision_text,
            "reason_code": self.reason_code,
            "reason": self.reason,
        }


class AuditLogger:
    def __init__(self, filepath: Optional[str] = None, redact: Optional[AuditRedactor] = None) -> None:
        self._log: list[AuditEntry] = []
        self._filepath: Optional[str] = filepath
        self._redact: Optional[AuditRedactor] = redact

    def record(self, tool: str, args: dict[str, Any], decision: Decision) -> None:
        audit_args = self._redact_args(args)
        entry = AuditEntry(
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            tool=tool,
            args=audit_args,
            decision=decision.allowed,
            decision_text="allow" if decision.allowed else "deny",
            reason=decision.reason,
            reason_code=decision.reason_code,
        )
        self._log.append(entry)
        if self._filepath is not None:
            self._write_jsonl(entry)

    def _write_jsonl(self, entry: AuditEntry) -> None:
        with open(self._filepath, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry.to_dict()) + "\n")

    @property
    def entries(self) -> list[AuditEntry]:
        return list(self._log)

    def clear(self) -> None:
        self._log.clear()

    def _redact_args(self, args: dict[str, Any]) -> dict[str, Any]:
        if self._redact is None:
            return dict(args)
        return self._redact(dict(args))
