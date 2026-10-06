from __future__ import annotations

import pytest

from apkguard.model import Severity
from apkguard.rules.manifest_backup import AllowBackupRule
from apkguard.rules.manifest_cleartext import CleartextTrafficRule
from apkguard.rules.manifest_debuggable import DebuggableRule
from apkguard.rules.manifest_exported import ExportedComponentRule
from apkguard.rules.manifest_sdk import OutdatedSdkRule

from helpers import ctx, manifest, run

# --- AG-MAN-001 debuggable -------------------------------------------------------------------


def test_debuggable_true_is_reported() -> None:
    findings = run(DebuggableRule(), ctx(manifest(app='android:debuggable="true"')))
    assert len(findings) == 1
    assert findings[0].rule_id == "AG-MAN-001"
    assert findings[0].severity is Severity.HIGH
    assert findings[0].location.file == "AndroidManifest.xml"


@pytest.mark.parametrize("app", ['android:debuggable="false"', ""])
def test_debuggable_false_or_missing_is_clean(app: str) -> None:
    assert run(DebuggableRule(), ctx(manifest(app=app))) == []


def test_debuggable_binary_xml_true_value() -> None:
    # androguard renders booleans from binary XML as "true"; tolerate raw 0xffffffff too.
    assert run(DebuggableRule(), ctx(manifest(app='android:debuggable="0xffffffff"')))


# --- AG-MAN-002 allowBackup ------------------------------------------------------------------


def test_allow_backup_true_without_rules_is_medium() -> None:
    findings = run(AllowBackupRule(), ctx(manifest(app='android:allowBackup="true"')))
    assert [f.severity for f in findings] == [Severity.MEDIUM]


def test_allow_backup_missing_defaults_to_true() -> None:
    findings = run(AllowBackupRule(), ctx(manifest(app="")))
    assert len(findings) == 1
    assert "defaults to true" in findings[0].message


def test_allow_backup_with_extraction_rules_is_low() -> None:
    m = manifest(app='android:allowBackup="true" android:dataExtractionRules="@xml/rules"')
    findings = run(AllowBackupRule(), ctx(m))
    assert [f.severity for f in findings] == [Severity.LOW]


def test_allow_backup_false_is_clean() -> None:
    assert run(AllowBackupRule(), ctx(manifest(app='android:allowBackup="false"'))) == []


# --- AG-MAN-003 cleartext --------------------------------------------------------------------


def test_cleartext_explicit_true() -> None:
    findings = run(CleartextTrafficRule(), ctx(manifest(app='android:usesCleartextTraffic="true"')))
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH


def test_cleartext_implicit_for_old_target_sdk() -> None:
    findings = run(CleartextTrafficRule(), ctx(manifest(target_sdk=27)))
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert "27" in findings[0].message


def test_cleartext_modern_target_sdk_is_clean() -> None:
    assert run(CleartextTrafficRule(), ctx(manifest(target_sdk=28))) == []


def test_cleartext_explicit_false_on_old_target_is_clean() -> None:
    m = manifest(app='android:usesCleartextTraffic="false"', target_sdk=23)
    assert run(CleartextTrafficRule(), ctx(m)) == []


def test_cleartext_network_security_config_base_config() -> None:
    nsc = (
        '<network-security-config><base-config cleartextTrafficPermitted="true"/>'
        "</network-security-config>"
    )
    findings = run(CleartextTrafficRule(), ctx(manifest(), nsc=nsc))
    assert len(findings) == 1
    assert findings[0].location.symbol == "base-config"
    assert findings[0].severity is Severity.HIGH


def test_cleartext_nsc_base_false_overrides_manifest_attribute() -> None:
    nsc = (
        '<network-security-config><base-config cleartextTrafficPermitted="false"/>'
        "</network-security-config>"
    )
    m = manifest(app='android:usesCleartextTraffic="true"')
    assert run(CleartextTrafficRule(), ctx(m, nsc=nsc)) == []


def test_cleartext_nsc_domain_config_is_low_and_lists_domains() -> None:
    nsc = (
        "<network-security-config>"
        '<domain-config cleartextTrafficPermitted="true"><domain>legacy.example.com</domain>'
        "</domain-config></network-security-config>"
    )
    findings = run(CleartextTrafficRule(), ctx(manifest(), nsc=nsc))
    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW
    assert "legacy.example.com" in findings[0].message


# --- AG-MAN-004 exported components ----------------------------------------------------------


def _exported(body: str, target_sdk: int = 35, top: str = "") -> list[str]:
    findings = run(
        ExportedComponentRule(), ctx(manifest(body=body, target_sdk=target_sdk, top=top))
    )
    return [f.location.symbol or "" for f in findings]


def test_exported_service_without_permission() -> None:
    body = '<service android:name=".SyncService" android:exported="true"/>'
    findings = run(ExportedComponentRule(), ctx(manifest(body=body)))
    assert len(findings) == 1
    assert findings[0].location.symbol == "com.example.app.SyncService"
    assert findings[0].severity is Severity.MEDIUM


def test_exported_provider_is_high() -> None:
    body = '<provider android:name="com.example.Data" android:exported="true"/>'
    findings = run(ExportedComponentRule(), ctx(manifest(body=body)))
    assert [f.severity for f in findings] == [Severity.HIGH]


def test_exported_with_permission_is_clean() -> None:
    body = (
        '<receiver android:name=".R" android:exported="true" '
        'android:permission="android.permission.BIND_JOB_SERVICE"/>'
    )
    assert _exported(body) == []


def test_exported_with_normal_custom_permission_is_reported() -> None:
    top = '<permission android:name="com.example.MY_PERM" android:protectionLevel="normal"/>'
    body = '<service android:name=".S" android:exported="true" android:permission="com.example.MY_PERM"/>'
    findings = run(ExportedComponentRule(), ctx(manifest(body=body, top=top)))
    assert len(findings) == 1
    assert "protectionLevel" in findings[0].message


def test_exported_with_signature_custom_permission_is_clean() -> None:
    top = '<permission android:name="com.example.MY_PERM" android:protectionLevel="signature"/>'
    body = '<service android:name=".S" android:exported="true" android:permission="com.example.MY_PERM"/>'
    assert _exported(body, top=top) == []


def test_launcher_activity_is_ignored() -> None:
    body = (
        '<activity android:name=".Main" android:exported="true"><intent-filter>'
        '<action android:name="android.intent.action.MAIN"/>'
        '<category android:name="android.intent.category.LAUNCHER"/>'
        "</intent-filter></activity>"
    )
    assert _exported(body) == []


def test_implicit_export_via_intent_filter() -> None:
    body = (
        '<receiver android:name=".BootReceiver"><intent-filter>'
        '<action android:name="android.intent.action.BOOT_COMPLETED"/>'
        "</intent-filter></receiver>"
    )
    assert _exported(body, target_sdk=30) == ["com.example.app.BootReceiver"]


def test_not_exported_component_is_clean() -> None:
    body = (
        '<service android:name=".S" android:exported="false"><intent-filter>'
        '<action android:name="x"/></intent-filter></service>'
    )
    assert _exported(body) == []


def test_provider_exported_by_default_on_old_target() -> None:
    body = '<provider android:name=".P" android:authorities="x"/>'
    assert _exported(body, target_sdk=16) == ["com.example.app.P"]
    assert _exported(body, target_sdk=17) == []


def test_provider_with_read_and_write_permission_is_clean() -> None:
    body = (
        '<provider android:name=".P" android:exported="true" '
        'android:readPermission="a.READ" android:writePermission="a.WRITE"/>'
    )
    assert _exported(body) == []


# --- AG-MAN-005 outdated SDK -----------------------------------------------------------------


def test_old_target_sdk_medium() -> None:
    findings = run(OutdatedSdkRule(), ctx(manifest(min_sdk=26, target_sdk=30)))
    assert [(f.location.symbol, f.severity) for f in findings] == [
        ("uses-sdk/targetSdkVersion", Severity.MEDIUM)
    ]


def test_very_old_target_sdk_high() -> None:
    findings = run(OutdatedSdkRule(), ctx(manifest(min_sdk=26, target_sdk=22)))
    assert findings[0].severity is Severity.HIGH


def test_low_min_sdk_is_low() -> None:
    findings = run(OutdatedSdkRule(), ctx(manifest(min_sdk=19, target_sdk=35)))
    assert [(f.location.symbol, f.severity) for f in findings] == [
        ("uses-sdk/minSdkVersion", Severity.LOW)
    ]


def test_modern_sdk_is_clean() -> None:
    assert run(OutdatedSdkRule(), ctx(manifest(min_sdk=24, target_sdk=35))) == []


def test_sdk_thresholds_are_configurable() -> None:
    rule = OutdatedSdkRule({"min_target_sdk": 36, "min_min_sdk": 21})
    findings = run(rule, ctx(manifest(min_sdk=21, target_sdk=35)))
    assert [f.location.symbol for f in findings] == ["uses-sdk/targetSdkVersion"]


def test_missing_target_sdk_defaults_to_min_sdk() -> None:
    findings = run(OutdatedSdkRule(), ctx(manifest(min_sdk=21, target_sdk=None)))
    assert {f.location.symbol for f in findings} == {
        "uses-sdk/targetSdkVersion",
        "uses-sdk/minSdkVersion",
    }
