"""Baseline files, fingerprint stability and the --baseline / --write-baseline CLI options."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from rich.console import Console

from apkguard.baseline import (
    NEW,
    UNCHANGED,
    Baseline,
    BaselineError,
    apply_baseline,
    baseline_document,
    load_baseline,
    write_baseline,
)
from apkguard.cli import main
from apkguard.config import Config, Suppression
from apkguard.model import Category, Finding, Location, Severity
from apkguard.reporters import render_html, render_json, render_sarif
from apkguard.reporters.terminal import print_table
from apkguard.rules.code_reflection import ReflectionRule
from apkguard.scanner import ScanResult, scan_context

from helpers import ctx, invoke, klass, manifest, method, run

SCHEMA = Path(__file__).parent.parent / "fixtures" / "sarif-schema-2.1.0.json"
FIXTURES = Path(__file__).parent.parent / "fixtures" / "apks"
NOTES = FIXTURES / "org.billthefarmer.notes_141.apk"  # has a HIGH cleartext finding
DIARY = FIXTURES / "org.billthefarmer.diary_1105.apk"  # has an app-specific code finding


def _finding(file: str = "classes.dex", symbol: str = "LA;->b", **kwargs: object) -> Finding:
    base: dict[str, object] = {
        "rule_id": "AG-X",
        "title": "t",
        "severity": Severity.HIGH,
        "category": Category.CODE,
        "message": "m",
        "location": Location(file, symbol),
        "remediation": "r",
        "evidence": "e",
    }
    base.update(kwargs)
    return Finding(**base)  # type: ignore[arg-type]


# --- fingerprint stability -----------------------------------------------------------------


def test_fingerprint_ignores_dex_file_number_message_and_severity() -> None:
    original = _finding("classes.dex")
    assert _finding("classes3.dex").fingerprint == original.fingerprint
    assert _finding(message="reworded", severity=Severity.LOW).fingerprint == original.fingerprint
    # ... but not the location, evidence or other non-DEX files
    assert _finding(symbol="LA;->c").fingerprint != original.fingerprint
    assert _finding(evidence="other").fingerprint != original.fingerprint
    assert _finding("assets/classes2.dex.txt").fingerprint != original.fingerprint


def test_reflection_fingerprint_does_not_depend_on_call_count() -> None:
    def reflective_class(calls: int) -> list[Finding]:
        lookups = [
            invoke("Ljava/lang/Class;->getMethod(Ljava/lang/String;)Ljava/lang/reflect/Method;", 0)
            for _ in range(calls)
        ]
        return run(ReflectionRule(), ctx(classes=[klass("LR;", method("LR;", "m", *lookups))]))

    eight, nine = reflective_class(8), reflective_class(9)
    assert "8 reflective calls" in eight[0].message and "9 reflective calls" in nine[0].message
    assert eight[0].fingerprint == nine[0].fingerprint


# --- baseline files ------------------------------------------------------------------------


def test_baseline_document_is_sorted_reviewable_and_skips_suppressed() -> None:
    findings = [
        _finding(symbol="LB;->x"),
        _finding(symbol="LA;->x"),
        _finding(symbol="LS;->x", suppressed=True),
    ]
    doc = baseline_document(findings, "com.example", "9.9")
    assert doc["format"] == "apkguard-baseline" and doc["version"] == 1
    assert doc["package"] == "com.example"
    entries = doc["findings"]
    assert len(entries) == 2
    assert [e["fingerprint"] for e in entries] == sorted(e["fingerprint"] for e in entries)
    assert set(entries[0]) == {"fingerprint", "rule_id", "severity", "location"}


def test_write_and_load_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "sub" / "baseline.json"
    findings = [_finding(symbol="LA;->x"), _finding(symbol="LB;->y")]
    assert write_baseline(path, findings, "com.example", "0.1.0") == 2
    baseline = load_baseline(path)
    assert baseline.fingerprints == {f.fingerprint for f in findings}
    assert baseline.package == "com.example"
    assert baseline.source == str(path)
    assert path.read_bytes().endswith(b"]\n}\n")  # LF line endings on every platform


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("not json", "not valid JSON"),
        ("[]", "not an APKGuard baseline"),
        ('{"format": "sarif"}', "not an APKGuard baseline"),
        ('{"format": "apkguard-baseline", "version": 2, "findings": []}', "unsupported"),
        ('{"format": "apkguard-baseline", "version": 1, "findings": [{"x": 1}]}', "fingerprint"),
        ('{"format": "apkguard-baseline", "version": 1}', "fingerprint"),
    ],
)
def test_invalid_baseline_files_are_rejected(tmp_path: Path, content: str, message: str) -> None:
    path = tmp_path / "b.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(BaselineError, match=message):
        load_baseline(path)


def test_missing_baseline_file(tmp_path: Path) -> None:
    with pytest.raises(BaselineError, match="not found"):
        load_baseline(tmp_path / "missing.json")


def test_apply_baseline_marks_new_and_unchanged_and_counts_absent() -> None:
    old, fixed, added = (
        _finding(symbol="LA;->x"),
        _finding(symbol="LF;->x"),
        _finding(symbol="LN;->x"),
    )
    baseline = Baseline(frozenset({old.fingerprint, fixed.fingerprint}))
    comparison = apply_baseline([old, added], baseline)
    assert (old.baseline_state, added.baseline_state) == (UNCHANGED, NEW)
    assert (comparison.new, comparison.unchanged, comparison.absent) == (1, 1, 1)


# --- scan results and reports --------------------------------------------------------------


def _vulnerable_result() -> ScanResult:
    m = manifest(
        app='android:debuggable="true" android:allowBackup="true"', permissions=["READ_SMS"]
    )
    config = Config(suppress=[Suppression("AG-MAN-002", reason="accepted")])
    return scan_context(ctx(m), config)


def test_unchanged_findings_do_not_gate() -> None:
    result = _vulnerable_result()
    assert result.exceeds(Severity.HIGH)
    baseline = Baseline(frozenset(f.fingerprint for f in result.active_findings))
    comparison = result.compare_with_baseline(baseline)
    assert comparison.new == 0 and comparison.unchanged == len(result.active_findings)
    assert not result.exceeds(Severity.INFO)
    assert result.gating_findings == []
    # suppressed findings are not compared (they are never written to a baseline)
    assert all(f.baseline_state is None for f in result.findings if f.suppressed)


def test_reports_show_baseline_state() -> None:
    result = _vulnerable_result()
    debuggable = next(f for f in result.findings if f.rule_id == "AG-MAN-001")
    result.compare_with_baseline(Baseline(frozenset({debuggable.fingerprint}), source="b.json"))

    data = json.loads(render_json(result))
    assert data["summary"]["baseline"] == {
        "file": "b.json",
        "new": len(result.active_findings) - 1,
        "unchanged": 1,
        "absent": 0,
    }
    states = {f["rule_id"]: f.get("baseline_state") for f in data["findings"]}
    assert states["AG-MAN-001"] == "unchanged"

    sarif = json.loads(render_sarif(result))
    sarif_states = {r["ruleId"]: r.get("baselineState") for r in sarif["runs"][0]["results"]}
    assert sarif_states["AG-MAN-001"] == "unchanged"
    assert "new" in sarif_states.values()
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.validate(sarif, json.loads(SCHEMA.read_text(encoding="utf-8")))

    assert "baseline: unchanged" in render_html(result)
    assert "1 unchanged since baseline" in render_html(result)

    console = Console(record=True, width=200)
    print_table(result, console)
    text = console.export_text()
    assert "AG-MAN-001" not in text  # unchanged findings are not listed
    assert "Baseline: 0 new" not in text and "1 unchanged" in text


def test_json_has_no_baseline_block_without_baseline() -> None:
    data = json.loads(render_json(_vulnerable_result()))
    assert data["summary"]["baseline"] is None
    assert all("baseline_state" not in f for f in data["findings"])


# --- CLI end to end (real F-Droid fixtures) ------------------------------------------------


@pytest.mark.integration
def test_cli_baseline_workflow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    assert main(["scan", str(NOTES), "-q"]) == 1  # HIGH cleartext finding

    # Creating a baseline accepts the current state, so it exits 0 even with findings.
    assert main(["scan", str(NOTES), "-q", "--write-baseline", "baseline.json"]) == 0
    assert "Wrote baseline with" in capsys.readouterr().err
    assert main(["scan", str(NOTES), "-q", "--baseline", "baseline.json"]) == 0

    # A baseline from another app: Diary's WebView finding is new, so it fails, with a warning.
    # (Manifest findings such as allowBackup have the same fingerprint in every app, which is
    # why baselines are per app.)
    assert main(["scan", str(DIARY), "-q", "--fail-on", "info", "--baseline", "baseline.json"]) == 1
    assert "baseline was created for org.billthefarmer.notes" in capsys.readouterr().err


def test_cli_baseline_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert main(["scan", "app.apk", "--baseline", "missing.json"]) == 2
    (tmp_path / "bad.json").write_text("{}", encoding="utf-8")
    assert main(["scan", "app.apk", "--baseline", "bad.json"]) == 2
