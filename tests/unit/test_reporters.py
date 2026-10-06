from __future__ import annotations

import json
from pathlib import Path

import pytest
from rich.console import Console

from apkguard.config import Config, Suppression
from apkguard.reporters import render_html, render_json, render_sarif
from apkguard.reporters.terminal import print_table
from apkguard.scanner import ScanResult, scan_context

from helpers import ctx, manifest

SCHEMA = Path(__file__).parent.parent / "fixtures" / "sarif-schema-2.1.0.json"


@pytest.fixture
def result() -> ScanResult:
    m = manifest(
        app='android:debuggable="true"',
        body='<service android:name="&lt;script&gt;alert(1)&lt;/script&gt;" '
        'android:exported="true"/>',
        permissions=["READ_SMS", "INTERNET", "RECEIVE_BOOT_COMPLETED"],
    )
    cfg = Config(suppress=[Suppression("AG-MAN-002", reason="tested elsewhere")])
    return scan_context(ctx(m), cfg)


def test_json_report_structure(result: ScanResult) -> None:
    data = json.loads(render_json(result))
    assert data["tool"]["name"] == "apkguard"
    assert data["apk"]["package"] == "com.example.app"
    assert data["summary"]["total"] == len(result.active_findings)
    assert data["summary"]["suppressed"] == 1
    assert data["summary"]["by_severity"]["high"] >= 2
    first = data["findings"][0]
    assert {"rule_id", "severity", "message", "location", "remediation", "fingerprint"} <= set(
        first
    )
    suppressed = [f for f in data["findings"] if f["suppressed"]]
    assert suppressed[0]["suppression_reason"] == "tested elsewhere"


def test_sarif_is_valid_against_official_schema(result: ScanResult) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    sarif = json.loads(render_sarif(result))
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    jsonschema.validate(sarif, schema)


def test_sarif_content(result: ScanResult) -> None:
    sarif = json.loads(render_sarif(result))
    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    rule_ids = [r["id"] for r in driver["rules"]]
    assert "AG-MAN-001" in rule_ids
    debug = next(r for r in run["results"] if r["ruleId"] == "AG-MAN-001")
    assert debug["level"] == "error"
    assert driver["rules"][debug["ruleIndex"]]["id"] == "AG-MAN-001"
    assert debug["properties"]["security-severity"] == "8.0"
    assert debug["partialFingerprints"]["apkguardFingerprint/v1"]
    rule = driver["rules"][debug["ruleIndex"]]
    assert "security" in rule["properties"]["tags"]
    assert rule["helpUri"].startswith("https://")
    suppressed = [r for r in run["results"] if "suppressions" in r]
    assert len(suppressed) == 1
    assert suppressed[0]["suppressions"][0]["justification"] == "tested elsewhere"


def test_sarif_fingerprints_are_stable(result: ScanResult) -> None:
    a = json.loads(render_sarif(result))["runs"][0]["results"]
    b = json.loads(render_sarif(result))["runs"][0]["results"]
    assert [r["partialFingerprints"] for r in a] == [r["partialFingerprints"] for r in b]


def test_html_report_is_standalone_and_escaped(result: ScanResult) -> None:
    html = render_html(result)
    assert html.startswith("<!doctype html>")
    assert "AG-MAN-001" in html
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    # No external resources: everything must be inline.
    assert "<link" not in html
    assert 'src="http' not in html


def test_html_report_without_findings() -> None:
    clean = scan_context(ctx(manifest(app='android:allowBackup="false"')))
    assert "No findings" in render_html(clean)


def test_terminal_table(result: ScanResult) -> None:
    console = Console(record=True, width=200, no_color=True)
    print_table(result, console)
    out = console.export_text()
    assert "AG-MAN-001" in out
    assert "Summary:" in out
    assert "(+1 suppressed)" in out
    assert "AG-MAN-002" not in out  # suppressed findings hidden by default

    console = Console(record=True, width=200, no_color=True)
    print_table(result, console, show_suppressed=True)
    assert "AG-MAN-002" in console.export_text()
