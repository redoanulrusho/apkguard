"""AG-PERM-002: suspicious combinations of permissions."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from apkguard.context import ApkContext
from apkguard.model import Category, Finding, Location, RuleMeta, Severity
from apkguard.rules.base import Rule

MANIFEST = "AndroidManifest.xml"
P = "android.permission."


@dataclass(frozen=True)
class Combination:
    name: str
    #: Every group must be satisfied; a group is satisfied if *any* permission in it is present.
    groups: tuple[frozenset[str], ...]
    severity: Severity
    rationale: str


def _g(*names: str) -> frozenset[str]:
    return frozenset(P + n for n in names)


INTERNET = _g("INTERNET")
BOOT = _g("RECEIVE_BOOT_COMPLETED")
SMS_READ = _g("READ_SMS", "RECEIVE_SMS")

COMBINATIONS: tuple[Combination, ...] = (
    Combination(
        "SMS interception with persistence",
        (SMS_READ, INTERNET, BOOT),
        Severity.HIGH,
        "can read incoming SMS (including one-time passcodes), start at boot and send data to "
        "the internet - a classic SMS-stealer / banking-trojan pattern",
    ),
    Combination(
        "Premium SMS sending",
        (_g("SEND_SMS"), INTERNET),
        Severity.HIGH,
        "can send SMS silently and be remote-controlled over the internet, enabling premium-rate "
        "SMS fraud",
    ),
    Combination(
        "Covert audio recording",
        (_g("RECORD_AUDIO"), INTERNET, BOOT),
        Severity.MEDIUM,
        "can record audio, start at boot and upload recordings",
    ),
    Combination(
        "Call log / contacts exfiltration",
        (_g("READ_CALL_LOG", "READ_CONTACTS"), INTERNET, BOOT),
        Severity.MEDIUM,
        "can read the call log or contacts, start at boot and upload them",
    ),
    Combination(
        "Background location tracking",
        (_g("ACCESS_BACKGROUND_LOCATION"), _g("ACCESS_FINE_LOCATION"), INTERNET),
        Severity.MEDIUM,
        "can track precise location while in the background and report it to a server",
    ),
    Combination(
        "Overlay with dropper capability",
        (_g("SYSTEM_ALERT_WINDOW"), _g("REQUEST_INSTALL_PACKAGES"), INTERNET),
        Severity.HIGH,
        "can draw over other apps and install downloaded APKs - typical of droppers and "
        "overlay-phishing malware",
    ),
    Combination(
        "Accessibility service with overlay",
        (_g("BIND_ACCESSIBILITY_SERVICE"), _g("SYSTEM_ALERT_WINDOW")),
        Severity.HIGH,
        "can read the screen, perform taps for the user and draw overlays - enough to take over "
        "the device UI",
    ),
)


class SuspiciousPermissionCombinationRule(Rule):
    meta = RuleMeta(
        id="AG-PERM-002",
        title="Suspicious permission combination",
        severity=Severity.HIGH,
        category=Category.PERMISSIONS,
        description=(
            "Some permissions are harmless alone but, combined, match capabilities commonly abused "
            "by spyware and banking malware (e.g. reading SMS + internet + start at boot). "
            "Legitimate apps can need them, but such combinations deserve explicit review and "
            "will be scrutinised by app-store review."
        ),
        remediation=(
            "Confirm every permission in the combination is required by a user-facing feature. "
            "Remove unused ones, replace SMS access with the SMS Retriever / User Consent APIs, "
            "and document the justification for reviewers."
        ),
        references=(
            "https://developer.android.com/guide/topics/permissions/default-handlers",
            "https://developers.google.com/identity/sms-retriever/overview",
            "https://support.google.com/googleplay/android-developer/answer/10208820",
        ),
        cwe="CWE-250",
        masvs="MASVS-PRIVACY-1",
    )

    def check(self, ctx: ApkContext) -> Iterable[Finding]:
        granted = set(ctx.manifest.permissions)
        # Permissions that guard the app's own services (e.g. accessibility) count as capabilities.
        granted |= {c.permission for c in ctx.manifest.components() if c.permission}
        for combo in COMBINATIONS:
            matched: list[str] = []
            for group in combo.groups:
                hits = sorted(group & granted)
                if not hits:
                    break
                matched.extend(hits)
            else:
                short = [m.removeprefix(P) for m in matched]
                yield self.finding(
                    f"{combo.name}: the app {combo.rationale} ({' + '.join(short)}).",
                    Location(MANIFEST, combo.name),
                    evidence=", ".join(matched),
                    severity=combo.severity,
                    permissions=matched,
                )
