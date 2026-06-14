import json

from agentguard.cli import run


def _write_policy_file(tmp_path):
    policy_file = tmp_path / "policy_file.py"
    policy_file.write_text(
        "\n".join(
            [
                "from agentguard import Policy, tool",
                "",
                "policy = Policy([",
                "    tool(\"send_email\", allow=lambda args: args[\"to\"].endswith(\"@mycompany.com\")),",
                "    tool(\"search\"),",
                "])",
                "",
                "def make_policy():",
                "    return policy",
            ],
        ),
        encoding="utf-8",
    )
    return policy_file


def test_check_command_allows_matching_policy(tmp_path, capsys):
    policy_file = _write_policy_file(tmp_path)

    exit_code = run(
        [
            "check",
            str(policy_file),
            "send_email",
            "--args",
            "{\"to\": \"alice@mycompany.com\"}",
        ],
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "ALLOW send_email" in captured.out


def test_check_command_denies_failing_policy(tmp_path, capsys):
    policy_file = _write_policy_file(tmp_path)

    exit_code = run(
        [
            "check",
            str(policy_file),
            "send_email",
            "--args",
            "{\"to\": \"attacker@evil.com\"}",
        ],
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "DENY send_email" in captured.out


def test_check_command_supports_json_output(tmp_path, capsys):
    policy_file = _write_policy_file(tmp_path)

    exit_code = run(["check", str(policy_file), "search", "--json"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["allowed"] is True
    assert payload["decision_text"] == "allow"
    assert payload["reason_code"] == "allowed_unconditional"


def test_check_command_supports_policy_factory(tmp_path, capsys):
    policy_file = _write_policy_file(tmp_path)

    exit_code = run(["check", str(policy_file), "search", "--policy", "make_policy"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "ALLOW search" in captured.out


def test_check_command_supports_args_file(tmp_path, capsys):
    policy_file = _write_policy_file(tmp_path)
    args_file = tmp_path / "args.json"
    args_file.write_text(json.dumps({"to": "alice@mycompany.com"}), encoding="utf-8")

    exit_code = run(["check", str(policy_file), "send_email", "--args-file", str(args_file)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "ALLOW send_email" in captured.out


def test_check_command_rejects_args_and_args_file_together(tmp_path, capsys):
    policy_file = _write_policy_file(tmp_path)
    args_file = tmp_path / "args.json"
    args_file.write_text(json.dumps({"to": "alice@mycompany.com"}), encoding="utf-8")

    exit_code = run(["check", str(policy_file), "send_email", "--args", "{}", "--args-file", str(args_file)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "use either --args or --args-file" in captured.err


def test_check_command_rejects_invalid_args_json(tmp_path, capsys):
    policy_file = _write_policy_file(tmp_path)

    exit_code = run(["check", str(policy_file), "search", "--args", "[]"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "--args must decode to a JSON object" in captured.err


def test_audit_command_prints_entries(tmp_path, capsys):
    audit_file = tmp_path / "audit.jsonl"
    audit_file.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "timestamp": "2026-01-01T00:00:00+00:00",
                        "tool": "send_email",
                        "decision": True,
                        "decision_text": "allow",
                        "reason": "send_email allowed",
                    },
                ),
                json.dumps(
                    {
                        "timestamp": "2026-01-01T00:00:01+00:00",
                        "tool": "send_email",
                        "decision": False,
                        "decision_text": "deny",
                        "reason": "send_email denied",
                    },
                ),
            ],
        ),
        encoding="utf-8",
    )

    exit_code = run(["audit", str(audit_file), "--decision", "deny"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "DENY send_email: send_email denied" in captured.out
    assert "ALLOW" not in captured.out


def test_audit_command_summarizes_filtered_entries(tmp_path, capsys):
    audit_file = tmp_path / "audit.jsonl"
    audit_file.write_text(
        "\n".join(
            [
                json.dumps({"tool": "send_email", "decision": True}),
                json.dumps({"tool": "send_email", "decision": False}),
                json.dumps({"tool": "transfer_funds", "decision": False}),
            ],
        ),
        encoding="utf-8",
    )

    exit_code = run(["audit", str(audit_file), "--tool", "send_email", "--summary", "--json"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload == {"total": 2, "allow": 1, "deny": 1}
