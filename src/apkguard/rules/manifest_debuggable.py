"""AG-MAN-001: application is debuggable."""

from __future__ import annotations

from collections.abc import Iterable

from apkguard.context import ApkContext, parse_bool
from apkguard.model import Category, Finding, Location, RuleMeta, Severity
from apkguard.rules.base import Rule

MANIFEST = "AndroidManifest.xml"


class DebuggableRule(Rule):
    meta = RuleMeta(
        id="AG-MAN-001",
        title="Application is debuggable",
        severity=Severity.HIGH,
        category=Category.MANIFEST,
        description=(
            'android:debuggable="true" lets anyone with USB/ADB access attach a debugger, '
            "inspect memory, run code as the app (run-as) and read its private data."
        ),
        remediation=(
            "Remove android:debuggable from the manifest and let the build system set it. "
            "Release builds produced by Gradle (`buildTypes.release`) are non-debuggable by "
            "default; make sure you ship a release build."
        ),
        references=(
            "https://developer.android.com/guide/topics/manifest/application-element#debug",
            "https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0039/",
        ),
        cwe="CWE-489",
        masvs="MASVS-RESILIENCE-4",
    )

    def check(self, ctx: ApkContext) -> Iterable[Finding]:
        raw = ctx.manifest.app_attr("debuggable")
        if parse_bool(raw):
            yield self.finding(
                'The <application> element sets android:debuggable="true".',
                Location(MANIFEST, "application"),
                evidence=f'android:debuggable="{raw}"',
            )
