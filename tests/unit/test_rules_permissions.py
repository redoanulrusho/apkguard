from __future__ import annotations

from apkguard.model import Severity
from apkguard.rules.permissions_combinations import SuspiciousPermissionCombinationRule
from apkguard.rules.permissions_dangerous import DangerousPermissionsRule

from helpers import ctx, manifest, run

# --- AG-PERM-001 dangerous permissions -------------------------------------------------------


def test_dangerous_permission_is_info() -> None:
    findings = run(DangerousPermissionsRule(), ctx(manifest(permissions=["CAMERA", "INTERNET"])))
    assert [(f.location.symbol, f.severity) for f in findings] == [
        ("android.permission.CAMERA", Severity.INFO)
    ]


def test_high_risk_permission_is_medium() -> None:
    findings = run(
        DangerousPermissionsRule(), ctx(manifest(permissions=["REQUEST_INSTALL_PACKAGES"]))
    )
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert "install other APKs" in findings[0].message


def test_normal_permissions_are_clean() -> None:
    m = manifest(permissions=["INTERNET", "ACCESS_NETWORK_STATE", "VIBRATE", "com.x.CUSTOM"])
    assert run(DangerousPermissionsRule(), ctx(m)) == []


def test_accessibility_service_binding_is_reported() -> None:
    body = (
        '<service android:name=".A11y" android:exported="true" '
        'android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"/>'
    )
    findings = run(DangerousPermissionsRule(), ctx(manifest(body=body)))
    assert [f.location.symbol for f in findings] == [
        "android.permission.BIND_ACCESSIBILITY_SERVICE"
    ]


# --- AG-PERM-002 combinations ----------------------------------------------------------------


def test_sms_internet_boot_combination_is_high() -> None:
    m = manifest(permissions=["RECEIVE_SMS", "INTERNET", "RECEIVE_BOOT_COMPLETED"])
    findings = run(SuspiciousPermissionCombinationRule(), ctx(m))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.HIGH
    assert finding.location.symbol == "SMS interception with persistence"
    assert "RECEIVE_SMS" in finding.message


def test_partial_combination_is_clean() -> None:
    m = manifest(permissions=["READ_SMS", "INTERNET"])  # no boot receiver
    assert run(SuspiciousPermissionCombinationRule(), ctx(m)) == []


def test_multiple_combinations_are_reported_separately() -> None:
    m = manifest(
        permissions=[
            "SEND_SMS", "READ_SMS", "INTERNET", "RECEIVE_BOOT_COMPLETED", "RECORD_AUDIO",
        ]
    )  # fmt: skip
    symbols = {f.location.symbol for f in run(SuspiciousPermissionCombinationRule(), ctx(m))}
    assert symbols == {
        "SMS interception with persistence",
        "Premium SMS sending",
        "Covert audio recording",
    }


def test_accessibility_plus_overlay_via_service_permission() -> None:
    body = (
        '<service android:name=".A" android:exported="true" '
        'android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"/>'
    )
    m = manifest(permissions=["SYSTEM_ALERT_WINDOW"], body=body)
    findings = run(SuspiciousPermissionCombinationRule(), ctx(m))
    assert [f.location.symbol for f in findings] == ["Accessibility service with overlay"]


def test_no_permissions_is_clean() -> None:
    assert run(SuspiciousPermissionCombinationRule(), ctx(manifest())) == []
