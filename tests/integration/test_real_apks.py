"""Integration tests against small, benign, open-source APKs downloaded from F-Droid.

See tests/fixtures/apks/README.md for provenance.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from apkguard.analysis import iter_calls
from apkguard.cli import main
from apkguard.config import Config
from apkguard.loader import ApkLoadError, load_apk
from apkguard.scanner import scan_apk

pytestmark = pytest.mark.integration

APKS = Path(__file__).parent.parent / "fixtures" / "apks"
EDITOR = APKS / "org.billthefarmer.editor_198.apk"
NOTES = APKS / "org.billthefarmer.notes_141.apk"
TUNER = APKS / "org.billthefarmer.tuner_158.apk"
DIARY = APKS / "org.billthefarmer.diary_1105.apk"
ALL = [EDITOR, NOTES, TUNER, DIARY]


@pytest.mark.parametrize("apk", ALL, ids=lambda p: p.stem)
def test_loader_parses_real_apk(apk: Path) -> None:
    ctx = load_apk(apk)
    assert ctx.manifest.package.startswith("org.billthefarmer.")
    assert ctx.manifest.target_sdk and ctx.manifest.target_sdk >= 21
    assert len(ctx.classes) > 10
    assert any(m.instructions for c in ctx.classes for m in c.methods)
    assert ctx.strings, "resource strings should be extracted"
    # Refs are normalised (no spaces in descriptors) so rules can match signatures.
    refs = [i.ref for c in ctx.classes for m in c.methods for i in m.instructions if i.ref]
    assert refs and not any(" " in r for r in refs)


def test_editor_expected_findings() -> None:
    result = scan_apk(EDITOR)
    found = {(f.rule_id, f.location.symbol) for f in result.findings}
    assert ("AG-MAN-002", "application") in found  # allowBackup="true"
    assert ("AG-MAN-005", "uses-sdk/minSdkVersion") in found  # minSdk 21
    assert ("AG-PERM-001", "android.permission.MANAGE_EXTERNAL_STORAGE") in found
    assert ("AG-MAN-004", "org.billthefarmer.editor.NewFile") in found
    # The launcher activity is exported by design and must not be flagged.
    assert ("AG-MAN-004", "org.billthefarmer.editor.Editor") not in found
    assert not any(f.rule_id == "AG-MAN-001" for f in result.findings)


def test_notes_cleartext_traffic() -> None:
    result = scan_apk(NOTES)
    cleartext = [f for f in result.findings if f.rule_id == "AG-MAN-003"]
    assert len(cleartext) == 1
    assert 'usesCleartextTraffic="true"' in (cleartext[0].evidence or "")


def test_diary_webview_javascript_detected_in_bytecode() -> None:
    """End-to-end check of the Dalvik pipeline: register tracking on real compiled code."""
    ctx = load_apk(DIARY)
    calls = [
        call
        for c in ctx.classes
        for m in c.methods
        for call in iter_calls(m)
        if call.short_target == "Landroid/webkit/WebSettings;->setJavaScriptEnabled"
    ]
    assert calls and calls[0].arg(0) == 1
    result = scan_apk(DIARY)
    js = [f for f in result.findings if f.rule_id == "AG-CODE-004"]
    assert js and js[0].location.symbol == "Lorg/billthefarmer/diary/Diary;->onCreate"
    # Diary targets API 28, below the default recommended level.
    assert any(f.rule_id == "AG-MAN-005" and "28" in f.message for f in result.findings)


def test_exclude_packages_skips_classes() -> None:
    full = load_apk(EDITOR)
    filtered = load_apk(EDITOR, exclude_packages=("Lorg/commonmark/",))
    assert len(filtered.classes) < len(full.classes)
    assert not any(c.name.startswith("Lorg/commonmark/") for c in filtered.classes)


def test_scan_is_fast_enough_for_ci() -> None:
    result = scan_apk(TUNER, Config())
    assert result.duration_s < 30


def test_invalid_apk_raises(tmp_path: Path) -> None:
    bogus = tmp_path / "bogus.apk"
    bogus.write_bytes(b"not a zip")
    with pytest.raises(ApkLoadError, match="not a valid APK"):
        load_apk(bogus)
    with pytest.raises(ApkLoadError, match="not found"):
        load_apk(tmp_path / "missing.apk")


# --- CLI end-to-end -------------------------------------------------------------------------


def test_cli_exit_codes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)  # make sure no stray .apkguard.yml is picked up
    # notes has a HIGH cleartext finding -> fails at the default threshold (high)
    assert main(["scan", str(NOTES), "-q"]) == 1
    assert main(["scan", str(NOTES), "-q", "--fail-on", "critical"]) == 0
    assert main(["scan", str(NOTES), "-q", "--fail-on", "none"]) == 0
    assert main(["scan", str(NOTES), "-q", "--disable", "AG-MAN-003"]) == 0
    # tuner has only medium/info findings
    assert main(["scan", str(TUNER), "-q"]) == 0
    assert main(["scan", str(TUNER), "-q", "--fail-on", "medium"]) == 1
    # errors
    assert main(["scan", str(tmp_path / "nope.apk")]) == 3
    assert main(["scan", str(TUNER), "--disable", "AG-BOGUS"]) == 2
    assert main([]) == 2


def test_cli_writes_all_reports(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    code = main([
        "scan", str(EDITOR), "-q", "--fail-on", "none",
        "--json", "out/r.json", "--sarif", "out/r.sarif", "--html", "out/r.html",
    ])  # fmt: skip
    assert code == 0
    data = json.loads((tmp_path / "out/r.json").read_text(encoding="utf-8"))
    assert data["apk"]["package"] == "org.billthefarmer.editor"
    sarif = json.loads((tmp_path / "out/r.sarif").read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert (tmp_path / "out/r.html").read_text(encoding="utf-8").startswith("<!doctype html>")


def test_cli_primary_format_to_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", str(TUNER), "--format", "json", "--no-config", "--fail-on", "none"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["apk"]["package"] == "org.billthefarmer.tuner"


def test_cli_config_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".apkguard.yml").write_text(
        "fail_on: medium\n"
        "suppress:\n"
        "  - rule: AG-MAN-002\n"
        "    reason: backups contain no sensitive data\n",
        encoding="utf-8",
    )
    # tuner's only medium finding is allowBackup, which is suppressed -> passes at 'medium'
    assert main(["scan", str(TUNER), "-q"]) == 0
    (tmp_path / ".apkguard.yml").write_text("fail_on: medium\n", encoding="utf-8")
    assert main(["scan", str(TUNER), "-q"]) == 1
    (tmp_path / ".apkguard.yml").write_text("fail_on: none\n", encoding="utf-8")
    assert main(["scan", str(NOTES), "-q"]) == 0  # config 'none' beats the default 'high'
    assert main(["scan", str(NOTES), "-q", "--fail-on", "high"]) == 1  # CLI beats config
    (tmp_path / ".apkguard.yml").write_text("bogus_key: 1\n", encoding="utf-8")
    assert main(["scan", str(TUNER), "-q"]) == 2


def test_cli_rules_command(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    assert "AG-MAN-001" in out and "AG-SEC-001" in out
