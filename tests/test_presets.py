from pathlib import Path

from agentguard.presets import (
    all_of,
    any_of,
    email_domain,
    not_,
    path_under,
    shell_command_allowlist,
    sql_readonly,
    url_host_in,
    value_in,
    value_lte,
)


def test_email_domain_allows_matching_domain():
    condition = email_domain("to", ["mycompany.com"])
    assert condition({"to": "alice@mycompany.com"}) is True


def test_email_domain_denies_external_domain():
    condition = email_domain("to", ["mycompany.com"])
    assert condition({"to": "attacker@evil.com"}) is False


def test_email_domain_accepts_domains_with_at_prefix():
    condition = email_domain("to", ["@mycompany.com"])
    assert condition({"to": "alice@mycompany.com"}) is True


def test_value_lte_allows_lower_value():
    condition = value_lte("amount", 1000)
    assert condition({"amount": 500}) is True


def test_value_lte_denies_higher_value():
    condition = value_lte("amount", 1000)
    assert condition({"amount": 50000}) is False


def test_value_in_allows_member():
    condition = value_in("role", ["reader", "writer"])
    assert condition({"role": "reader"}) is True


def test_value_in_denies_non_member():
    condition = value_in("role", ["reader", "writer"])
    assert condition({"role": "admin"}) is False


def test_path_under_allows_relative_path_inside_root(tmp_path):
    condition = path_under("path", tmp_path)
    assert condition({"path": "notes/report.txt"}) is True


def test_path_under_denies_absolute_path_outside_root(tmp_path):
    condition = path_under("path", tmp_path)
    outside = Path(tmp_path).parent / "outside.txt"
    assert condition({"path": str(outside)}) is False


def test_url_host_in_allows_matching_host():
    condition = url_host_in("url", ["api.mycompany.com"])
    assert condition({"url": "https://api.mycompany.com/v1"}) is True


def test_url_host_in_denies_other_host():
    condition = url_host_in("url", ["api.mycompany.com"])
    assert condition({"url": "https://evil.com/v1"}) is False


def test_sql_readonly_allows_select():
    condition = sql_readonly()
    assert condition({"query": "SELECT * FROM customers"}) is True


def test_sql_readonly_denies_delete():
    condition = sql_readonly()
    assert condition({"query": "DELETE FROM customers"}) is False


def test_sql_readonly_denies_mutation_inside_cte():
    condition = sql_readonly()
    assert condition({"query": "WITH changed AS (UPDATE users SET admin = true) SELECT * FROM changed"}) is False


def test_shell_command_allowlist_allows_prefix():
    condition = shell_command_allowlist(prefixes=["git status", "uv run pytest"])
    assert condition({"command": "uv run pytest tests/test_policy.py"}) is True


def test_shell_command_allowlist_denies_other_command():
    condition = shell_command_allowlist(prefixes=["git status"])
    assert condition({"command": "git push origin main"}) is False


def test_all_of_requires_all_conditions():
    condition = all_of(value_lte("amount", 1000), value_in("currency", ["USD"]))
    assert condition({"amount": 500, "currency": "USD"}) is True
    assert condition({"amount": 500, "currency": "EUR"}) is False


def test_any_of_requires_one_condition():
    condition = any_of(value_in("role", ["admin"]), value_in("role", ["owner"]))
    assert condition({"role": "owner"}) is True
    assert condition({"role": "reader"}) is False


def test_not_inverts_condition():
    condition = not_(value_in("role", ["admin"]))
    assert condition({"role": "reader"}) is True
    assert condition({"role": "admin"}) is False
