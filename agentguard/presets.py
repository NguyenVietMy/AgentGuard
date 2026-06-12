import re
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import urlparse

Condition = Callable[[dict[str, Any]], bool]

_MUTATING_SQL_KEYWORDS = re.compile(
    r"\b(alter|create|delete|drop|grant|insert|merge|revoke|truncate|update)\b",
    re.IGNORECASE,
)
_READONLY_SQL_START = re.compile(r"^\s*(select|with|explain)\b", re.IGNORECASE)


def all_of(*conditions: Condition) -> Condition:
    def condition(args: dict[str, Any]) -> bool:
        return all(check(args) for check in conditions)

    return condition


def any_of(*conditions: Condition) -> Condition:
    def condition(args: dict[str, Any]) -> bool:
        return any(check(args) for check in conditions)

    return condition


def not_(condition: Condition) -> Condition:
    def inverted(args: dict[str, Any]) -> bool:
        return not condition(args)

    return inverted


def email_domain(arg: str, domains: Iterable[str]) -> Condition:
    allowed_domains = {_normalize_domain(domain) for domain in domains}

    def condition(args: dict[str, Any]) -> bool:
        value = args[arg]
        if not isinstance(value, str) or "@" not in value:
            return False
        domain = value.rsplit("@", maxsplit=1)[1].lower()
        return domain in allowed_domains

    return condition


def value_in(arg: str, allowed_values: Iterable[Any]) -> Condition:
    allowed_set = set(allowed_values)

    def condition(args: dict[str, Any]) -> bool:
        return args[arg] in allowed_set

    return condition


def value_lte(arg: str, max_value: int | float) -> Condition:
    def condition(args: dict[str, Any]) -> bool:
        value = args[arg]
        return isinstance(value, int | float) and value <= max_value

    return condition


def path_under(arg: str, root: str | Path) -> Condition:
    root_path = Path(root).resolve()

    def condition(args: dict[str, Any]) -> bool:
        value = args[arg]
        if not isinstance(value, str):
            return False

        candidate = Path(value)
        if not candidate.is_absolute():
            candidate = root_path / candidate

        return candidate.resolve().is_relative_to(root_path)

    return condition


def url_host_in(arg: str, hosts: Iterable[str]) -> Condition:
    allowed_hosts = {host.lower() for host in hosts}

    def condition(args: dict[str, Any]) -> bool:
        value = args[arg]
        if not isinstance(value, str):
            return False

        parsed = urlparse(value)
        return parsed.hostname is not None and parsed.hostname.lower() in allowed_hosts

    return condition


def sql_readonly(arg: str = "query") -> Condition:
    def condition(args: dict[str, Any]) -> bool:
        query = args[arg]
        if not isinstance(query, str):
            return False

        normalized = query.strip()
        if not _READONLY_SQL_START.search(normalized):
            return False

        return _MUTATING_SQL_KEYWORDS.search(normalized) is None

    return condition


def shell_command_allowlist(arg: str = "command", prefixes: Iterable[str] = ()) -> Condition:
    allowed_prefixes = tuple(prefix.strip() for prefix in prefixes if prefix.strip())

    def condition(args: dict[str, Any]) -> bool:
        command = args[arg]
        if not isinstance(command, str):
            return False

        normalized = command.strip()
        return any(normalized == prefix or normalized.startswith(f"{prefix} ") for prefix in allowed_prefixes)

    return condition


def _normalize_domain(domain: str) -> str:
    return domain.removeprefix("@").lower()
