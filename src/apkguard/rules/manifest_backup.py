"""AG-MAN-002: application data can be backed up."""

from __future__ import annotations

from collections.abc import Iterable

from apkguard.context import ApkContext, parse_bool
from apkguard.model import Category, Finding, Location, RuleMeta, Severity
from apkguard.rules.base import Rule

MANIFEST = "AndroidManifest.xml"


class AllowBackupRule(Rule):
    meta = RuleMeta(
        id="AG-MAN-002",
        title="Application data backup is enabled",
        severity=Severity.MEDIUM,
        category=Category.MANIFEST,
        description=(
            "When android:allowBackup is true (the default when the attribute is missing), the "
            "app's private files, databases and shared preferences can be extracted through "
            "cloud backup or device-to-device transfer, and on older devices via `adb backup`."
        ),
        remediation=(
            'Set android:allowBackup="false", or keep it enabled but restrict what is backed up '
            "with android:fullBackupContent (Android 11 and lower) and android:dataExtractionRules "
            "(Android 12+), excluding tokens, credentials and other sensitive files."
        ),
        references=(
            "https://developer.android.com/guide/topics/data/autobackup",
            "https://developer.android.com/about/versions/12/backup-restore",
        ),
        cwe="CWE-530",
        masvs="MASVS-STORAGE-2",
    )

    def check(self, ctx: ApkContext) -> Iterable[Finding]:
        manifest = ctx.manifest
        if manifest.application is None:
            return
        raw = manifest.app_attr("allowBackup")
        enabled = parse_bool(raw)
        if enabled is False:
            return
        has_rules = bool(
            manifest.app_attr("fullBackupContent") or manifest.app_attr("dataExtractionRules")
        )
        if raw is None:
            message = "android:allowBackup is not set, so it defaults to true."
            evidence = "android:allowBackup not set"
        else:
            message = f'The <application> element sets android:allowBackup="{raw}".'
            evidence = f'android:allowBackup="{raw}"'
        if has_rules:
            yield self.finding(
                message + " Backup rules (fullBackupContent/dataExtractionRules) are defined; "
                "verify they exclude sensitive data.",
                Location(MANIFEST, "application"),
                evidence=evidence,
                severity=Severity.LOW,
            )
        else:
            yield self.finding(
                message + " No backup rules restrict which files are included.",
                Location(MANIFEST, "application"),
                evidence=evidence,
            )
