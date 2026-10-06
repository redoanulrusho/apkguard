"""AG-PERM-001: dangerous / high-risk permissions requested."""

from __future__ import annotations

from collections.abc import Iterable

from apkguard.context import ApkContext
from apkguard.model import Category, Finding, Location, RuleMeta, Severity
from apkguard.rules.base import Rule

MANIFEST = "AndroidManifest.xml"
P = "android.permission."

# Runtime ("dangerous") permissions from the Android platform.
DANGEROUS_PERMISSIONS: frozenset[str] = frozenset(
    P + name
    for name in (
        "READ_CALENDAR", "WRITE_CALENDAR", "CAMERA", "READ_CONTACTS", "WRITE_CONTACTS",
        "GET_ACCOUNTS", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
        "ACCESS_BACKGROUND_LOCATION", "RECORD_AUDIO", "READ_PHONE_STATE", "READ_PHONE_NUMBERS",
        "CALL_PHONE", "ANSWER_PHONE_CALLS", "READ_CALL_LOG", "WRITE_CALL_LOG",
        "ADD_VOICEMAIL", "USE_SIP", "PROCESS_OUTGOING_CALLS", "BODY_SENSORS",
        "BODY_SENSORS_BACKGROUND", "SEND_SMS", "RECEIVE_SMS", "READ_SMS", "RECEIVE_WAP_PUSH",
        "RECEIVE_MMS", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "READ_MEDIA_IMAGES",
        "READ_MEDIA_VIDEO", "READ_MEDIA_AUDIO", "ACCESS_MEDIA_LOCATION", "ACTIVITY_RECOGNITION",
        "BLUETOOTH_SCAN", "BLUETOOTH_CONNECT", "BLUETOOTH_ADVERTISE", "NEARBY_WIFI_DEVICES",
        "UWB_RANGING", "POST_NOTIFICATIONS",
    )
)  # fmt: skip

# Special / signature|privileged-style permissions that grant unusually broad power.
HIGH_RISK_PERMISSIONS: dict[str, str] = {
    P + "SYSTEM_ALERT_WINDOW": "draw over other apps (overlay / tapjacking)",
    P + "REQUEST_INSTALL_PACKAGES": "install other APKs",
    P + "MANAGE_EXTERNAL_STORAGE": "read and write all files on shared storage",
    P + "WRITE_SETTINGS": "modify system settings",
    P + "PACKAGE_USAGE_STATS": "observe which apps the user runs",
    P + "QUERY_ALL_PACKAGES": "enumerate all installed apps",
    P + "BIND_ACCESSIBILITY_SERVICE": "read screen content and perform actions for the user",
    P + "BIND_DEVICE_ADMIN": "act as device administrator",
    P + "BIND_NOTIFICATION_LISTENER_SERVICE": "read all notifications (including OTP codes)",
    P + "READ_LOGS": "read system logs",
    P + "INSTALL_PACKAGES": "silently install packages",
}


class DangerousPermissionsRule(Rule):
    meta = RuleMeta(
        id="AG-PERM-001",
        title="Dangerous or high-risk permissions requested",
        severity=Severity.INFO,
        category=Category.PERMISSIONS,
        description=(
            "Lists runtime (dangerous) permissions and special high-risk permissions requested by "
            "the app. Each one widens the impact of a compromise and draws user and store-review "
            "scrutiny; they should match the app's documented functionality."
        ),
        remediation=(
            "Remove permissions that are not strictly needed (check transitive library manifests "
            "with the merged-manifest view), prefer privacy-preserving alternatives (photo picker, "
            "Storage Access Framework, coarse location) and request runtime permissions only when "
            "the feature is used."
        ),
        references=(
            "https://developer.android.com/guide/topics/permissions/overview",
            "https://developer.android.com/privacy-and-security/minimize-permission-requests",
        ),
        cwe="CWE-250",
        masvs="MASVS-PRIVACY-1",
    )

    def check(self, ctx: ApkContext) -> Iterable[Finding]:
        requested = ctx.manifest.permissions
        services_perms = {c.permission for c in ctx.manifest.components() if c.permission}
        for perm in requested:
            if perm in HIGH_RISK_PERMISSIONS:
                yield self.finding(
                    f"Requests high-risk permission {perm}: allows the app to "
                    f"{HIGH_RISK_PERMISSIONS[perm]}.",
                    Location(MANIFEST, perm),
                    evidence=f'<uses-permission android:name="{perm}"/>',
                    severity=Severity.MEDIUM,
                )
            elif perm in DANGEROUS_PERMISSIONS:
                yield self.finding(
                    f"Requests dangerous (runtime) permission {perm}.",
                    Location(MANIFEST, perm),
                    evidence=f'<uses-permission android:name="{perm}"/>',
                )
        # Accessibility / notification listener / device admin are bound via service permission.
        for perm in sorted(services_perms & HIGH_RISK_PERMISSIONS.keys()):
            if perm in requested:
                continue
            yield self.finding(
                f"Declares a service bound with {perm}: allows the app to "
                f"{HIGH_RISK_PERMISSIONS[perm]}.",
                Location(MANIFEST, perm),
                evidence=f'android:permission="{perm}"',
                severity=Severity.MEDIUM,
            )
