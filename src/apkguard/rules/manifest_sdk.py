"""AG-MAN-005: outdated minSdkVersion / targetSdkVersion."""

from __future__ import annotations

from collections.abc import Iterable
from typing import ClassVar

from apkguard.context import ApkContext
from apkguard.model import Category, Finding, Location, RuleMeta, Severity
from apkguard.rules.base import Rule

MANIFEST = "AndroidManifest.xml"


class OutdatedSdkRule(Rule):
    meta = RuleMeta(
        id="AG-MAN-005",
        title="Outdated SDK version",
        severity=Severity.MEDIUM,
        category=Category.MANIFEST,
        description=(
            "A low targetSdkVersion opts the app out of platform security defaults introduced in "
            "newer Android versions (e.g. cleartext blocked by default at API 28, explicit "
            "component export at API 31, safer PendingIntents and broadcast restrictions). A low "
            "minSdkVersion allows installation on devices that no longer receive security "
            "patches and lack runtime permissions (API < 23)."
        ),
        remediation=(
            "Raise targetSdkVersion to the level currently required by Google Play and test the "
            "behaviour changes. Consider raising minSdkVersion to at least 23 so that runtime "
            "permissions and modern TLS defaults are always available."
        ),
        references=(
            "https://developer.android.com/google/play/requirements/target-sdk",
            "https://developer.android.com/guide/topics/manifest/uses-sdk-element",
        ),
        cwe="CWE-1104",
        masvs="MASVS-CODE-1",
    )
    default_options: ClassVar[dict[str, object]] = {
        "min_target_sdk": 34,
        "critical_target_sdk": 28,
        "min_min_sdk": 23,
    }

    def check(self, ctx: ApkContext) -> Iterable[Finding]:
        manifest = ctx.manifest
        target, minimum = manifest.target_sdk, manifest.min_sdk
        want_target = self.option_int("min_target_sdk")
        if target is not None and target < want_target:
            severity = (
                Severity.HIGH
                if target < self.option_int("critical_target_sdk")
                else Severity.MEDIUM
            )
            yield self.finding(
                f"targetSdkVersion is {target}; at least {want_target} is recommended.",
                Location(MANIFEST, "uses-sdk/targetSdkVersion"),
                evidence=f"targetSdkVersion={target}",
                severity=severity,
            )
        want_min = self.option_int("min_min_sdk")
        if minimum is not None and minimum < want_min:
            yield self.finding(
                f"minSdkVersion is {minimum}; the app can run on Android versions without "
                f"current security patches (recommended minimum: {want_min}).",
                Location(MANIFEST, "uses-sdk/minSdkVersion"),
                evidence=f"minSdkVersion={minimum}",
                severity=Severity.LOW,
            )
