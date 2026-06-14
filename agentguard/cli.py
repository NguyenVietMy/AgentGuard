import argparse
import importlib.util
import json
import sys
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path
from types import ModuleType
from typing import Any, TextIO

from agentguard.policy import Decision, Policy


class CliError(Exception):
    pass


class AgentGuardArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise CliError(message)


def main(argv: Sequence[str] | None = None) -> int:
    return run(argv, stdout=sys.stdout, stderr=sys.stderr)


def run(argv: Sequence[str] | None = None, stdout: TextIO | None = None, stderr: TextIO | None = None) -> int:
    output = stdout if stdout is not None else sys.stdout
    errors = stderr if stderr is not None else sys.stderr

    try:
        args = _build_parser().parse_args(argv)
        return args.handler(args, output)
    except CliError as exc:
        print(f"error: {exc}", file=errors)
        return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = AgentGuardArgumentParser(
        prog="agentguard",
        description="Check AgentGuard policy decisions and inspect audit logs.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    check = subcommands.add_parser("check", help="Check one tool call against a Python policy file.")
    check.add_argument("policy_file", help="Path to a Python file containing an agentguard Policy.")
    check.add_argument("tool_name", help="Tool name to check.")
    check.add_argument("--args", help="Tool arguments as a JSON object. Defaults to '{}'.")
    check.add_argument("--args-file", help="Path to a JSON file containing tool arguments.")
    check.add_argument(
        "--policy",
        default="policy",
        help="Policy variable or zero-argument factory name in the policy file. Defaults to 'policy'.",
    )
    check.add_argument("--json", action="store_true", help="Emit the decision as JSON.")
    check.set_defaults(handler=_handle_check)

    audit = subcommands.add_parser("audit", help="Inspect an AgentGuard JSONL audit log.")
    audit.add_argument("audit_file", help="Path to an AgentGuard JSONL audit log.")
    audit.add_argument("--tool", help="Only show entries for this tool.")
    audit.add_argument(
        "--decision",
        choices=("all", "allow", "deny"),
        default="all",
        help="Filter by decision. Defaults to all.",
    )
    audit.add_argument("--limit", type=int, help="Show at most this many entries after filtering.")
    audit.add_argument("--summary", action="store_true", help="Show aggregate counts instead of entries.")
    audit.add_argument("--json", action="store_true", help="Emit entries or summary as JSON.")
    audit.set_defaults(handler=_handle_audit)

    return parser


def _handle_check(args: argparse.Namespace, stdout: TextIO) -> int:
    policy = _load_policy(args.policy_file, args.policy)
    tool_args = _load_tool_args(args.args, args.args_file)
    decision = policy.check(args.tool_name, tool_args)

    if args.json:
        print(json.dumps(_decision_to_dict(decision)), file=stdout)
    else:
        status = "ALLOW" if decision.allowed else "DENY"
        print(f"{status} {decision.tool_name}: {decision.reason}", file=stdout)

    return 0 if decision.allowed else 1


def _handle_audit(args: argparse.Namespace, stdout: TextIO) -> int:
    if args.limit is not None and args.limit < 0:
        raise CliError("--limit must be greater than or equal to 0")

    entries = _load_audit_entries(args.audit_file)
    filtered_entries = _filter_audit_entries(entries, tool=args.tool, decision=args.decision)

    if args.limit is not None:
        filtered_entries = filtered_entries[: args.limit]

    if args.summary:
        summary = _summarize_audit_entries(filtered_entries)
        if args.json:
            print(json.dumps(summary), file=stdout)
        else:
            print(
                f"total={summary['total']} allow={summary['allow']} deny={summary['deny']}",
                file=stdout,
            )
        return 0

    if args.json:
        print(json.dumps(filtered_entries), file=stdout)
        return 0

    for entry in filtered_entries:
        decision_text = _entry_decision_text(entry)
        timestamp = str(entry.get("timestamp", ""))
        tool_name = str(entry.get("tool", ""))
        reason = str(entry.get("reason", ""))
        print(f"{timestamp} {decision_text.upper()} {tool_name}: {reason}", file=stdout)

    return 0


def _load_policy(policy_file: str, policy_name: str) -> Policy:
    module = _load_module(policy_file)

    if not hasattr(module, policy_name):
        raise CliError(f"{policy_file} does not define {policy_name!r}")

    policy_candidate = getattr(module, policy_name)
    if isinstance(policy_candidate, Policy):
        return policy_candidate

    if callable(policy_candidate):
        try:
            policy_candidate = policy_candidate()
        except Exception as exc:
            raise CliError(f"{policy_name!r} raised {type(exc).__name__}: {exc}") from exc
        if isinstance(policy_candidate, Policy):
            return policy_candidate

    raise CliError(f"{policy_name!r} must be a Policy or a zero-argument callable returning Policy")


def _load_module(policy_file: str) -> ModuleType:
    path = Path(policy_file).expanduser().resolve()
    if not path.exists():
        raise CliError(f"policy file not found: {policy_file}")
    if not path.is_file():
        raise CliError(f"policy path is not a file: {policy_file}")

    spec = importlib.util.spec_from_file_location(f"_agentguard_policy_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise CliError(f"could not load policy file: {policy_file}")

    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise CliError(f"policy file raised {type(exc).__name__}: {exc}") from exc
    finally:
        sys.path.pop(0)

    return module


def _load_tool_args(args_json: str | None, args_file: str | None) -> dict[str, Any]:
    if args_json is not None and args_file is not None:
        raise CliError("use either --args or --args-file, not both")

    if args_file is not None:
        return _load_args_file(args_file)

    return _parse_args_json(args_json if args_json is not None else "{}")


def _load_args_file(args_file: str) -> dict[str, Any]:
    path = Path(args_file).expanduser().resolve()
    if not path.exists():
        raise CliError(f"args file not found: {args_file}")
    if not path.is_file():
        raise CliError(f"args path is not a file: {args_file}")

    try:
        contents = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CliError(f"could not read args file: {exc}") from exc

    return _parse_args_json(contents)


def _parse_args_json(args_json: str) -> dict[str, Any]:
    try:
        parsed = json.loads(args_json)
    except json.JSONDecodeError as exc:
        raise CliError(f"--args must be valid JSON: {exc.msg}") from exc

    if not isinstance(parsed, dict):
        raise CliError("--args must decode to a JSON object")

    return parsed


def _decision_to_dict(decision: Decision) -> dict[str, Any]:
    data = asdict(decision)
    data["decision_text"] = "allow" if decision.allowed else "deny"
    return data


def _load_audit_entries(audit_file: str) -> list[dict[str, Any]]:
    path = Path(audit_file).expanduser().resolve()
    if not path.exists():
        raise CliError(f"audit file not found: {audit_file}")
    if not path.is_file():
        raise CliError(f"audit path is not a file: {audit_file}")

    entries: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise CliError(f"{audit_file}:{line_number} is not valid JSON: {exc.msg}") from exc
            if not isinstance(parsed, dict):
                raise CliError(f"{audit_file}:{line_number} must be a JSON object")
            entries.append(parsed)

    return entries


def _filter_audit_entries(
    entries: list[dict[str, Any]],
    tool: str | None,
    decision: str,
) -> list[dict[str, Any]]:
    filtered: list[dict[str, Any]] = []

    for entry in entries:
        if tool is not None and entry.get("tool") != tool:
            continue
        if decision != "all" and _entry_decision_text(entry) != decision:
            continue
        filtered.append(entry)

    return filtered


def _entry_decision_text(entry: dict[str, Any]) -> str:
    decision_text = entry.get("decision_text")
    if decision_text in ("allow", "deny"):
        return decision_text
    return "allow" if entry.get("decision") is True else "deny"


def _summarize_audit_entries(entries: list[dict[str, Any]]) -> dict[str, int]:
    allow_count = sum(1 for entry in entries if _entry_decision_text(entry) == "allow")
    deny_count = sum(1 for entry in entries if _entry_decision_text(entry) == "deny")
    return {
        "total": len(entries),
        "allow": allow_count,
        "deny": deny_count,
    }
