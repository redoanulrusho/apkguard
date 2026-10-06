"""AG-MAN-003: cleartext (HTTP) network traffic is allowed."""

from __future__ import annotations

from collections.abc import Iterable

from apkguard.context import ApkContext, parse_bool
from apkguard.model import Category, Finding, Location, RuleMeta, Severity
from apkguard.rules.base import Rule

MANIFEST = "AndroidManifest.xml"


class CleartextTrafficRule(Rule):
    meta = RuleMeta(
        id="AG-MAN-003",
        title="Cleartext network traffic allowed",
        severity=Severity.HIGH,
        category=Category.MANIFEST,
        description=(
            "The app permits unencrypted HTTP traffic, either explicitly "
            '(android:usesCleartextTraffic="true", or cleartextTrafficPermitted in the network '
            "security config) or implicitly by targeting API level 27 or lower. Traffic sent "
            "over HTTP can be read and modified by anyone on the network path."
        ),
        remediation=(
            'Use HTTPS for all connections. Remove android:usesCleartextTraffic="true" and set '
            'cleartextTrafficPermitted="false" in the network security config base-config. If a '
            "legacy host truly requires HTTP, allow it only for that domain with a <domain-config>."
        ),
        references=(
            "https://developer.android.com/privacy-and-security/security-config",
            "https://developer.android.com/guide/topics/manifest/application-element#usesCleartextTraffic",
        ),
        cwe="CWE-319",
        masvs="MASVS-NETWORK-1",
    )

    def check(self, ctx: ApkContext) -> Iterable[Finding]:
        manifest = ctx.manifest
        if manifest.application is None:
            return
        nsc = ctx.network_security_config
        nsc_file = ctx.network_security_config_path or "res/xml/network_security_config.xml"
        base_from_nsc: bool | None = None
        if nsc is not None:
            base = nsc.find("base-config")
            if base is not None:
                base_from_nsc = parse_bool(base.get("cleartextTrafficPermitted"))
            for domain_cfg in nsc.iter("domain-config"):
                if parse_bool(domain_cfg.get("cleartextTrafficPermitted")):
                    domains = [d.text.strip() for d in domain_cfg.findall("domain") if d.text]
                    yield self.finding(
                        "The network security config allows cleartext traffic for specific "
                        f"domains: {', '.join(domains) or '<none listed>'}.",
                        Location(nsc_file, "domain-config"),
                        evidence='cleartextTrafficPermitted="true"',
                        severity=Severity.LOW,
                        domains=domains,
                    )

        if base_from_nsc is True:
            yield self.finding(
                "The network security config base-config allows cleartext traffic for all domains.",
                Location(nsc_file, "base-config"),
                evidence='<base-config cleartextTrafficPermitted="true">',
            )
            return
        if base_from_nsc is False:
            return

        raw = manifest.app_attr("usesCleartextTraffic")
        explicit = parse_bool(raw)
        if explicit is True:
            yield self.finding(
                'The <application> element sets android:usesCleartextTraffic="true".',
                Location(MANIFEST, "application"),
                evidence=f'android:usesCleartextTraffic="{raw}"',
            )
        elif explicit is None and (manifest.target_sdk or 1) < 28:
            yield self.finding(
                f"The app targets API level {manifest.target_sdk} (< 28), where cleartext traffic "
                "is allowed by default, and does not disable it.",
                Location(MANIFEST, "uses-sdk"),
                evidence=f"targetSdkVersion={manifest.target_sdk}",
                severity=Severity.MEDIUM,
            )
