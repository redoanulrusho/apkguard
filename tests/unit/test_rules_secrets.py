from __future__ import annotations

import pytest

from apkguard.context import StringItem
from apkguard.model import Severity
from apkguard.rules.secrets_hardcoded import HardcodedSecretRule, redact, shannon_entropy

from helpers import const_string, ctx, run, single_method_class

# Fake, syntactically valid test values (not real credentials).
AWS = "AKIA" + "IOSFODNN7EXAMPLE"
GOOGLE = "AIza" + "SyD-abcdefghijklmnopqrstuvwxyz01234"
STRIPE = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
GITHUB = "ghp_" + "a" * 36


def _strings(*items: StringItem):  # type: ignore[no-untyped-def]
    return run(HardcodedSecretRule(), ctx(strings=items))


@pytest.mark.parametrize(
    ("value", "name", "severity"),
    [
        (AWS, "AWS access key ID", Severity.HIGH),
        (GOOGLE, "Google API key", Severity.MEDIUM),
        (STRIPE, "Stripe secret key", Severity.CRITICAL),
        (GITHUB, "GitHub token", Severity.HIGH),
        ("-----BEGIN RSA PRIVATE KEY-----", "Private key", Severity.CRITICAL),
        ("https://admin:hunter22@db.example.com/x", "Credentials in URL", Severity.HIGH),
    ],
)
def test_known_patterns_in_asset(value: str, name: str, severity: Severity) -> None:
    findings = _strings(StringItem(f'{{"key": "{value}"}}', "assets/config.json", "line 1"))
    assert len(findings) == 1
    f = findings[0]
    assert f.extra["secret_type"] == name
    assert f.severity is severity
    assert f.location.file == "assets/config.json"


def test_secret_in_dex_const_string() -> None:
    cls = single_method_class("Lcom/example/Api;", const_string(0, f"Bearer {GITHUB}"))
    findings = run(HardcodedSecretRule(), ctx(classes=[cls]))
    assert len(findings) == 1
    assert findings[0].location.symbol == "Lcom/example/Api;->run"


def test_secret_value_is_redacted_in_evidence() -> None:
    findings = _strings(StringItem(AWS, "res/values/strings.xml", "string/aws"))
    assert AWS not in (findings[0].evidence or "")
    assert findings[0].evidence.startswith("AKIA")  # type: ignore[union-attr]


def test_google_services_key_is_downgraded_to_low() -> None:
    findings = _strings(StringItem(GOOGLE, "res/values/strings.xml", "string/google_api_key"))
    assert [f.severity for f in findings] == [Severity.LOW]


def test_duplicate_secret_reported_once() -> None:
    item = StringItem(AWS, "assets/a.json", "line 1")
    assert len(_strings(item, StringItem(AWS, "assets/b.json", "line 3"))) == 1


def test_generic_high_entropy_named_resource() -> None:
    findings = _strings(
        StringItem("q8Xz3LmP0vRt7YwK2nB5sD9f", "res/values/strings.xml", "string/backend_api_key")
    )
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].extra["secret_type"] == "Generic secret"


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("string/api_key", "your_api_key_here_xxxxx"),  # placeholder
        ("string/password_hint", "Enter your password"),  # prose
        ("string/token_label", "aaaaaaaaaaaaaaaaaaaa"),  # low entropy
        ("string/app_name", "q8Xz3LmP0vRt7YwK2nB5sD9f"),  # name not secret-like
    ],
)
def test_generic_check_avoids_false_positives(name: str, value: str) -> None:
    assert _strings(StringItem(value, "res/values/strings.xml", name)) == []


def test_ordinary_strings_are_clean() -> None:
    items = [
        StringItem("https://example.com/api/v1/users", "assets/endpoints.txt", "line 1"),
        StringItem("Lorem ipsum dolor sit amet", "res/values/strings.xml", "string/lorem"),
    ]
    assert _strings(*items) == []


def test_entropy_and_redact_helpers() -> None:
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("abcd") == 2
    assert redact("short") == "*****"
    assert redact("abcdefghijklmnop") == "abcd...op (len 16)"
