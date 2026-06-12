import json

from agentguard.audit import AuditLogger
from agentguard.policy import Decision


def _allowed_decision() -> Decision:
    return Decision(
        allowed=True,
        reason="test_tool allowed unconditionally",
        denial_message="",
        tool_name="test_tool",
        reason_code="allowed_unconditional",
    )


def _denied_decision() -> Decision:
    return Decision(
        allowed=False,
        reason="test_tool denied: allow condition returned False",
        denial_message="Action 'test_tool' is not permitted.",
        tool_name="test_tool",
        reason_code="condition_failed",
    )


def test_record_allowed_decision():
    logger = AuditLogger()
    logger.record("test_tool", {"key": "val"}, _allowed_decision())
    assert len(logger.entries) == 1
    assert logger.entries[0].decision is True


def test_record_denied_decision():
    logger = AuditLogger()
    logger.record("test_tool", {"key": "val"}, _denied_decision())
    assert len(logger.entries) == 1
    assert logger.entries[0].decision is False


def test_entries_returns_both():
    logger = AuditLogger()
    logger.record("tool_a", {}, _allowed_decision())
    logger.record("tool_b", {}, _denied_decision())
    assert len(logger.entries) == 2


def test_entries_in_order():
    logger = AuditLogger()
    logger.record("first", {}, _allowed_decision())
    logger.record("second", {}, _denied_decision())
    assert logger.entries[0].tool == "first"
    assert logger.entries[1].tool == "second"


def test_entries_is_defensive_copy():
    logger = AuditLogger()
    logger.record("test_tool", {}, _allowed_decision())
    entries = logger.entries
    entries.clear()
    assert len(logger.entries) == 1


def test_timestamp_is_iso8601_utc():
    logger = AuditLogger()
    logger.record("test_tool", {}, _allowed_decision())
    ts = logger.entries[0].timestamp
    assert "+00:00" in ts or "Z" in ts


def test_jsonl_file_written(tmp_path):
    filepath = str(tmp_path / "audit.jsonl")
    logger = AuditLogger(filepath=filepath)
    logger.record("test_tool", {"key": "val"}, _allowed_decision())
    with open(filepath, encoding="utf-8") as f:
        lines = f.readlines()
    assert len(lines) == 1


def test_jsonl_file_appends_not_overwrites(tmp_path):
    filepath = str(tmp_path / "audit.jsonl")
    logger = AuditLogger(filepath=filepath)
    logger.record("tool_a", {}, _allowed_decision())
    logger.record("tool_b", {}, _denied_decision())
    with open(filepath, encoding="utf-8") as f:
        lines = f.readlines()
    assert len(lines) == 2


def test_jsonl_valid_json_per_line(tmp_path):
    filepath = str(tmp_path / "audit.jsonl")
    logger = AuditLogger(filepath=filepath)
    logger.record("tool_a", {"x": 1}, _allowed_decision())
    logger.record("tool_b", {"y": 2}, _denied_decision())
    with open(filepath, encoding="utf-8") as f:
        for line in f:
            parsed = json.loads(line)
            assert "timestamp" in parsed
            assert "tool" in parsed
            assert "args" in parsed
            assert "decision" in parsed
            assert "reason" in parsed


def test_clear_empties_log():
    logger = AuditLogger()
    logger.record("test_tool", {}, _allowed_decision())
    logger.clear()
    assert len(logger.entries) == 0


def test_no_file_when_filepath_is_none(tmp_path):
    logger = AuditLogger()
    logger.record("test_tool", {}, _allowed_decision())
    import os
    assert not any(f.endswith(".jsonl") for f in os.listdir(tmp_path))


def test_args_preserved_in_entry():
    logger = AuditLogger()
    logger.record("test_tool", {"to": "alice@example.com", "amount": 500}, _allowed_decision())
    entry = logger.entries[0]
    assert entry.args == {"to": "alice@example.com", "amount": 500}


def test_reason_preserved_in_entry():
    logger = AuditLogger()
    logger.record("test_tool", {}, _denied_decision())
    entry = logger.entries[0]
    assert "allow condition returned False" in entry.reason


def test_entry_includes_schema_version_decision_text_and_reason_code():
    logger = AuditLogger()
    logger.record("test_tool", {}, _denied_decision())
    entry = logger.entries[0]
    assert entry.schema_version == "1.0"
    assert entry.decision_text == "deny"
    assert entry.reason_code == "condition_failed"


def test_jsonl_includes_schema_version_decision_text_and_reason_code(tmp_path):
    filepath = str(tmp_path / "audit.jsonl")
    logger = AuditLogger(filepath=filepath)
    logger.record("test_tool", {}, _denied_decision())
    with open(filepath, encoding="utf-8") as f:
        parsed = json.loads(f.readline())
    assert parsed["schema_version"] == "1.0"
    assert parsed["decision_text"] == "deny"
    assert parsed["reason_code"] == "condition_failed"


def test_redactor_masks_sensitive_args():
    logger = AuditLogger(redact=lambda args: {**args, "body": "[REDACTED]"})
    logger.record("send_email", {"to": "alice@example.com", "body": "secret"}, _allowed_decision())
    assert logger.entries[0].args == {"to": "alice@example.com", "body": "[REDACTED]"}
