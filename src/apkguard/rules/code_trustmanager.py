"""AG-CODE-008: TrustManager that accepts every certificate."""

from __future__ import annotations

from collections.abc import Iterable

from apkguard.analysis import is_empty_body
from apkguard.context import ApkContext
from apkguard.model import Category, Finding, RuleMeta, Severity
from apkguard.rules._util import iter_methods, method_location
from apkguard.rules.base import Rule

TRUST_MANAGER_TYPES = (
    "Ljavax/net/ssl/X509TrustManager;",
    "Ljavax/net/ssl/X509ExtendedTrustManager;",
)


class InsecureTrustManagerRule(Rule):
    meta = RuleMeta(
        id="AG-CODE-008",
        title="Insecure TrustManager",
        severity=Severity.HIGH,
        category=Category.CODE,
        description=(
            "A custom X509TrustManager implements checkServerTrusted with an empty body, so "
            "every server certificate - including self-signed or attacker-issued ones - is "
            "accepted. Any network attacker can intercept and modify TLS traffic."
        ),
        remediation=(
            "Remove the custom TrustManager and rely on the platform default. To trust a "
            "private CA or pin certificates, declare it in the network security config "
            "(<trust-anchors>, <pin-set>) instead of writing TLS validation code."
        ),
        references=(
            "https://developer.android.com/privacy-and-security/risks/unsafe-trustmanager",
            "https://developer.android.com/privacy-and-security/security-ssl",
        ),
        cwe="CWE-295",
        masvs="MASVS-NETWORK-1",
    )

    def check(self, ctx: ApkContext) -> Iterable[Finding]:
        for cls, method in iter_methods(ctx):
            if method.name != "checkServerTrusted":
                continue
            if not (set(cls.interfaces) & set(TRUST_MANAGER_TYPES)) and (
                cls.superclass not in TRUST_MANAGER_TYPES
            ):
                continue
            if is_empty_body(method):
                yield self.finding(
                    f"{cls.name}.checkServerTrusted() does not validate the certificate chain "
                    "(empty method body).",
                    method_location(cls, method),
                    evidence=f"{method.full_name}: return-void",
                )
