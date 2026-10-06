from __future__ import annotations

from collections.abc import Iterable

from apkguard.config import Config, Suppression
from apkguard.context import ApkContext
from apkguard.model import Finding, Severity
from apkguard.rules import ALL_RULES, RULES_BY_ID
from apkguard.rules.base import Rule
from apkguard.scanner import build_rules, run_rules, scan_context

from helpers import ctx, manifest

VULNERABLE = manifest(
    app='android:debuggable="true" android:allowBackup="true"',
    permissions=["READ_SMS", "INTERNET", "RECEIVE_BOOT_COMPLETED"],
)


def test_rule_ids_are_unique_and_well_formed() -> None:
    ids = [r.meta.id for r in ALL_RULES]
    assert len(ids) == len(set(ids))
    for rule in ALL_RULES:
        meta = rule.meta
        assert meta.id.startswith("AG-")
        assert meta.title and meta.description and meta.remediation
        assert meta.references, f"{meta.id} has no references"
        assert meta.cwe and meta.cwe.startswith("CWE-")


def test_every_rule_has_a_unit_test() -> None:
    """Guard against adding a rule without tests: each rule ID or class must be referenced."""
    from pathlib import Path

    test_sources = "\n".join(
        p.read_text(encoding="utf-8") for p in (Path(__file__).parent).glob("test_rules_*.py")
    )
    missing = [r.meta.id for r in ALL_RULES if r.__name__ not in test_sources]
    assert missing == []


def test_scan_context_reports_and_sorts_by_severity() -> None:
    result = scan_context(ctx(VULNERABLE))
    ids = {f.rule_id for f in result.findings}
    assert {"AG-MAN-001", "AG-MAN-002", "AG-PERM-002"} <= ids
    severities = [f.severity for f in result.findings]
    assert severities == sorted(severities, reverse=True)
    assert result.package == "com.example.app"
    assert result.exceeds(Severity.HIGH)
    assert not result.exceeds(None)


def test_disable_rule() -> None:
    result = scan_context(ctx(VULNERABLE), Config(disable={"AG-MAN-001"}))
    assert "AG-MAN-001" not in {f.rule_id for f in result.findings}
    assert "AG-MAN-001" not in {m.id for m in result.rules}


def test_severity_override() -> None:
    result = scan_context(ctx(VULNERABLE), Config(severity_overrides={"AG-MAN-001": Severity.LOW}))
    debug = next(f for f in result.findings if f.rule_id == "AG-MAN-001")
    assert debug.severity is Severity.LOW


def test_suppressed_findings_do_not_count_towards_threshold() -> None:
    cfg = Config(
        suppress=[
            Suppression("AG-MAN-001", reason="debug build"),
            Suppression("AG-PERM-002"),
            Suppression("AG-MAN-003"),
        ]
    )
    result = scan_context(ctx(VULNERABLE), cfg)
    debug = next(f for f in result.findings if f.rule_id == "AG-MAN-001")
    assert debug.suppressed and debug.suppression_reason == "debug build"
    assert not result.exceeds(Severity.HIGH)
    assert result.exceeds(Severity.MEDIUM)  # allowBackup is still active
    assert result.counts()["high"] == 0


def test_rule_options_are_passed_to_rules() -> None:
    rules = build_rules(Config(rule_options={"AG-CODE-002": {"threshold": 99}}))
    reflection = next(r for r in rules if r.meta.id == "AG-CODE-002")
    assert reflection.options["threshold"] == 99


class _BrokenRule(Rule):
    meta = RULES_BY_ID["AG-MAN-001"].meta

    def check(self, ctx: ApkContext) -> Iterable[Finding]:
        raise RuntimeError("boom")


def test_broken_rule_is_reported_not_raised(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import apkguard.scanner as scanner

    monkeypatch.setattr(scanner, "ALL_RULES", (_BrokenRule,))
    findings, _metas, errors = run_rules(ctx(VULNERABLE), Config())
    assert findings == []
    assert errors[0].rule_id == "AG-MAN-001"
    assert "boom" in errors[0].error


def test_clean_app_has_no_findings_above_info() -> None:
    clean = manifest(app='android:allowBackup="false"', min_sdk=26, target_sdk=35)
    result = scan_context(ctx(clean))
    assert result.findings == []
    assert not result.exceeds(Severity.INFO)
