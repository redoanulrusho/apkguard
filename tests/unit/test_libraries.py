"""Library detection: classification, scanner modes, config, CLI and reports."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from rich.console import Console

from apkguard.cli import main
from apkguard.config import Config, ConfigError, parse_config
from apkguard.context import ApkContext, ClassInfo
from apkguard.libraries import (
    DEFAULT_LIBRARY_PACKAGES,
    LibraryMode,
    class_name_of,
    match_library,
)
from apkguard.model import Category, Finding, Location, Severity
from apkguard.reporters import render_html, render_json, render_sarif
from apkguard.reporters.terminal import print_table
from apkguard.scanner import ScanResult, scan_context

from helpers import ctx, klass, manifest, method, ret_void

TRUST_ALL = "Ljavax/net/ssl/X509TrustManager;"


def _finding(file: str, symbol: str | None, **extra: object) -> Finding:
    return Finding(
        rule_id="AG-X",
        title="t",
        severity=Severity.LOW,
        category=Category.CODE,
        message="m",
        location=Location(file, symbol),
        remediation="r",
        extra=dict(extra),
    )


# --- classification ----------------------------------------------------------------------


def test_class_name_from_smali_method_symbol() -> None:
    finding = _finding("classes2.dex", "Landroidx/core/app/Foo;->bar")
    assert class_name_of(finding) == "androidx.core.app.Foo"


def test_class_name_from_component_finding() -> None:
    finding = _finding("AndroidManifest.xml", "x", component="androidx.work.Receiver")
    assert class_name_of(finding) == "androidx.work.Receiver"


def test_permission_and_application_findings_are_not_classified() -> None:
    # "com.google.android.c2dm.permission.RECEIVE" looks like a library package but is a
    # permission requested by the app, so it must stay app-owned.
    assert class_name_of(_finding("AndroidManifest.xml", "com.google.x.permission.Y")) is None
    assert class_name_of(_finding("AndroidManifest.xml", "application")) is None
    assert class_name_of(_finding("classes.dex", None)) is None
    assert class_name_of(_finding("classes.dex", "not-smali")) is None


def test_match_library_uses_whole_package_segments() -> None:
    assert match_library("kotlin.io.FilesKt", DEFAULT_LIBRARY_PACKAGES) == "kotlin"
    assert match_library("kotlinapp.Main", DEFAULT_LIBRARY_PACKAGES) is None
    assert match_library("com.example.app.Main", DEFAULT_LIBRARY_PACKAGES) is None


def test_match_library_prefers_most_specific_package() -> None:
    packages = ("com.google", "com.google.android.gms")
    assert match_library("com.google.android.gms.ads.X", packages) == "com.google.android.gms"


def test_app_package_is_never_a_library() -> None:
    # An app whose own package starts with a library prefix (e.g. zxing's Barcode Scanner).
    app = "com.google.zxing.client.android"
    assert match_library("com.google.zxing.client.android.Capture", ("com.google",), app) is None
    assert match_library("com.google.zxing.Reader", ("com.google",), app) == "com.google"


# --- scanner modes -------------------------------------------------------------------------


def _trust_all_class(name: str) -> ClassInfo:
    """A class whose checkServerTrusted() accepts every certificate (an AG-CODE-008 finding)."""
    return klass(name, method(name, "checkServerTrusted", ret_void()), interfaces=[TRUST_ALL])


def _app_with_library_finding() -> ApkContext:
    """An app with one insecure TrustManager in its own code and one inside OkHttp."""
    return ctx(
        manifest(app='android:allowBackup="false"'),
        classes=[
            _trust_all_class("Lcom/example/app/Net;"),
            _trust_all_class("Lokhttp3/internal/Trust;"),
        ],
    )


def _scan(mode: LibraryMode) -> ScanResult:
    return scan_context(_app_with_library_finding(), Config(library_mode=mode))


def test_separate_mode_keeps_library_findings_out_of_the_gate() -> None:
    result = _scan(LibraryMode.SEPARATE)
    libraries = {
        f.location.symbol: f.library for f in result.findings if f.rule_id == "AG-CODE-008"
    }
    assert libraries == {"Lcom/example/app/Net;->checkServerTrusted": None,
                         "Lokhttp3/internal/Trust;->checkServerTrusted": "okhttp3"}  # fmt: skip
    assert [f.library for f in result.separated_findings] == ["okhttp3"]
    assert all(f.library is None for f in result.gating_findings)
    assert result.counts()["high"] == 1
    assert result.library_counts() == {"okhttp3": 1}


def test_separate_mode_does_not_fail_on_library_only_findings() -> None:
    context = _app_with_library_finding()
    context.classes = context.classes[1:]  # keep only the OkHttp class
    result = scan_context(context, Config())
    assert not result.exceeds(Severity.HIGH)
    assert scan_context(context, Config(library_mode=LibraryMode.INCLUDE)).exceeds(Severity.HIGH)


def test_include_mode_counts_library_findings_but_still_tags_them() -> None:
    result = _scan(LibraryMode.INCLUDE)
    assert result.counts()["high"] == 2
    assert result.separated_findings == []
    assert sorted(str(f.library) for f in result.findings if f.rule_id == "AG-CODE-008") == [
        "None",
        "okhttp3",
    ]


def test_exclude_mode_drops_library_findings() -> None:
    result = _scan(LibraryMode.EXCLUDE)
    assert [f.library for f in result.findings if f.rule_id == "AG-CODE-008"] == [None]


def test_exported_library_component_is_tagged() -> None:
    m = manifest(
        app='android:allowBackup="false"',
        body='<receiver android:name="androidx.media.session.MediaButtonReceiver" '
        'android:exported="true"/>',
    )
    result = scan_context(ctx(m))
    exported = next(f for f in result.findings if f.rule_id == "AG-MAN-004")
    assert exported.library == "androidx"
    assert result.is_separated(exported)


# --- configuration -------------------------------------------------------------------------


def test_config_library_options() -> None:
    config = parse_config(
        {"library_findings": "Exclude", "library_packages": ["com.vendor.sdk", "Lnet/acme/"]}
    )
    assert config.library_mode is LibraryMode.EXCLUDE
    assert config.library_packages[: len(DEFAULT_LIBRARY_PACKAGES)] == DEFAULT_LIBRARY_PACKAGES
    assert config.library_packages[-2:] == ("com.vendor.sdk", "net.acme")
    assert Config().library_mode is LibraryMode.SEPARATE


@pytest.mark.parametrize(
    "raw",
    [{"library_findings": "hide"}, {"library_packages": "androidx"}, {"library_packages": [1]}],
)
def test_config_library_options_are_validated(raw: dict[str, object]) -> None:
    with pytest.raises(ConfigError):
        parse_config(raw)


# --- reports -------------------------------------------------------------------------------


def test_reports_mark_library_findings() -> None:
    result = _scan(LibraryMode.SEPARATE)

    data = json.loads(render_json(result))
    assert data["summary"]["library_findings"] == {
        "mode": "separate",
        "separated": 1,
        "by_library": {"okhttp3": 1},
    }
    okhttp = next(f for f in data["findings"] if f["library"] == "okhttp3")
    assert okhttp["origin"] == "library"

    sarif = json.loads(render_sarif(result))
    results = sarif["runs"][0]["results"]
    lib = next(r for r in results if r["properties"]["origin"] == "library")
    assert "okhttp3" in lib["suppressions"][0]["justification"]
    app = next(
        r for r in results if r["ruleId"] == "AG-CODE-008" and r["properties"]["origin"] == "app"
    )
    assert "suppressions" not in app

    html = render_html(result)
    assert "library: okhttp3" in html
    assert "1 in third-party libraries" in html


def test_terminal_hides_separated_findings_with_a_note() -> None:
    console = Console(record=True, width=200)
    print_table(_scan(LibraryMode.SEPARATE), console)
    text = console.export_text()
    assert "okhttp3/internal" not in text
    assert "Not shown: 1 finding(s) in third-party libraries (okhttp3 1)" in text

    console = Console(record=True, width=200)
    print_table(_scan(LibraryMode.INCLUDE), console)
    assert "[okhttp3]" in console.export_text()


# --- CLI -----------------------------------------------------------------------------------


def test_cli_library_flags(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import apkguard.scanner as scanner

    monkeypatch.chdir(tmp_path)
    context = _app_with_library_finding()
    context.classes = context.classes[1:]  # only the OkHttp finding is high
    monkeypatch.setattr(scanner, "load_apk", lambda path, exclude_packages=(): context)

    assert main(["scan", "app.apk", "-q"]) == 0  # separated by default
    assert main(["scan", "app.apk", "-q", "--library-findings", "include"]) == 1
    (tmp_path / ".apkguard.yml").write_text("library_findings: include\n", encoding="utf-8")
    assert main(["scan", "app.apk", "-q"]) == 1
    assert main(["scan", "app.apk", "-q", "--library-findings", "separate"]) == 0  # CLI wins


def test_cli_library_package_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import apkguard.scanner as scanner

    monkeypatch.chdir(tmp_path)
    vendored = ctx(
        manifest(app='android:allowBackup="false"'),
        classes=[_trust_all_class("Lcom/vendor/sdk/Net;")],
    )
    monkeypatch.setattr(scanner, "load_apk", lambda path, exclude_packages=(): vendored)

    assert main(["scan", "app.apk", "-q"]) == 1
    assert main(["scan", "app.apk", "-q", "--library-package", "com.vendor.sdk"]) == 0
