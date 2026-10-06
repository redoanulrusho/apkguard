from __future__ import annotations

from pathlib import Path

import pytest

from apkguard.config import (
    Config,
    ConfigError,
    Suppression,
    find_config,
    load_config,
    parse_config,
    to_smali_prefix,
)
from apkguard.model import Finding, Location, Severity
from apkguard.rules import RULES_BY_ID

KNOWN = set(RULES_BY_ID)


def _finding(rule: str = "AG-MAN-004", file: str = "AndroidManifest.xml",
             symbol: str | None = "com.example.DeepLink") -> Finding:  # fmt: skip
    return Finding(rule, "t", Severity.LOW, "manifest", "m", Location(file, symbol), "r")


def test_full_config_parses() -> None:
    cfg = parse_config(
        {
            "fail_on": "medium",
            "disable": ["AG-PERM-001"],
            "severity_overrides": {"AG-MAN-005": "info"},
            "exclude_packages": ["com.google.android.gms", "Lokhttp3/"],
            "rule_options": {"AG-CODE-002": {"threshold": 3}},
            "suppress": [{"rule": "AG-MAN-004", "location": "*.DeepLink", "reason": "ok"}],
        },
        KNOWN,
    )
    assert cfg.fail_on is Severity.MEDIUM
    assert cfg.disable == {"AG-PERM-001"}
    assert cfg.severity_overrides == {"AG-MAN-005": Severity.INFO}
    assert cfg.exclude_packages == ("Lcom/google/android/gms/", "Lokhttp3/")
    assert cfg.rule_options == {"AG-CODE-002": {"threshold": 3}}
    assert cfg.suppress[0].reason == "ok"


def test_fail_on_none() -> None:
    cfg = parse_config({"fail_on": "none"})
    assert cfg.fail_on is None
    assert cfg.fail_on_set
    assert not parse_config({}).fail_on_set


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ({"unknown": 1}, "unknown config key"),
        ({"disable": ["AG-NOPE-999"]}, "unknown rule id"),
        ({"disable": "AG-MAN-001"}, "must be a list"),
        ({"fail_on": "severe"}, "unknown severity"),
        ({"severity_overrides": {"AG-MAN-001": "urgent"}}, "unknown severity"),
        ({"suppress": [{"location": "x"}]}, "needs at least a 'rule'"),
        ({"suppress": [{"rule": "AG-MAN-001", "path": "x"}]}, "unknown key"),
        ({"rule_options": {"AG-CODE-002": 5}}, "rule_options"),
        ({"rule_options": {"AG-CODE-002": {"treshold": 3}}}, "unknown option"),
        ({"rule_options": {"AG-CODE-002": {"threshold": "high"}}}, "expected a number"),
        ({"rule_options": {"AG-MAN-005": {"min_target_sdk": 34.5}}}, "expected an integer"),
        ({"rule_options": {"AG-MAN-001": {"anything": 1}}}, "valid: none"),
        ([], "mapping"),
    ],
)
def test_invalid_configs_raise(raw: object, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        parse_config(raw, KNOWN)


def test_suppression_matching() -> None:
    f = _finding()
    assert Suppression("AG-MAN-004").matches(f)
    assert Suppression("*").matches(f)
    assert Suppression("AG-MAN-004", "*.DeepLink").matches(f)
    assert Suppression("AG-MAN-004", "AndroidManifest.xml").matches(f)
    assert Suppression("AG-MAN-004", "AndroidManifest.xml:com.example.*").matches(f)
    assert not Suppression("AG-MAN-001").matches(f)
    assert not Suppression("AG-MAN-004", "*.Other").matches(f)


def test_config_suppression_for_returns_first_match() -> None:
    cfg = Config(suppress=[Suppression("AG-MAN-001"), Suppression("AG-MAN-004", reason="a")])
    sup = cfg.suppression_for(_finding())
    assert sup is not None and sup.reason == "a"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("com.google", "Lcom/google/"),
        ("com.google.*", "Lcom/google/"),
        ("Lcom/google/", "Lcom/google/"),
        ("Lcom/google", "Lcom/google/"),
    ],
)
def test_to_smali_prefix(raw: str, expected: str) -> None:
    assert to_smali_prefix(raw) == expected


def test_load_config_from_file(tmp_path: Path) -> None:
    path = tmp_path / ".apkguard.yml"
    path.write_text("fail_on: low\ndisable: [AG-MAN-002]\n", encoding="utf-8")
    cfg = load_config(path, KNOWN)
    assert cfg.fail_on is Severity.LOW
    assert cfg.source == str(path)
    assert find_config(tmp_path) == path


def test_load_config_missing_and_invalid(tmp_path: Path) -> None:
    assert load_config(None).disable == set()
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "missing.yml")
    bad = tmp_path / "bad.yml"
    bad.write_text("disable: [unclosed\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid YAML"):
        load_config(bad)


def test_empty_file_is_default_config(tmp_path: Path) -> None:
    path = tmp_path / "empty.yml"
    path.write_text("", encoding="utf-8")
    assert load_config(path).suppress == []
    assert find_config(tmp_path) is None
