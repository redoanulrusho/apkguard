"""AG-CODE-009: HostnameVerifier that accepts every host."""

from __future__ import annotations

from collections.abc import Iterable

from apkguard.analysis import returns_constant
from apkguard.context import ApkContext
from apkguard.model import Category, Finding, RuleMeta, Severity
from apkguard.rules._util import iter_methods, method_location
from apkguard.rules.base import Rule

HOSTNAME_VERIFIER = "Ljavax/net/ssl/HostnameVerifier;"
ALLOW_ALL_MARKERS = ("ALLOW_ALL_HOSTNAME_VERIFIER", "AllowAllHostnameVerifier;")


class InsecureHostnameVerifierRule(Rule):
    meta = RuleMeta(
        id="AG-CODE-009",
        title="Insecure HostnameVerifier",
        severity=Severity.HIGH,
        category=Category.CODE,
        description=(
            "A HostnameVerifier whose verify() always returns true, or the deprecated "
            "ALLOW_ALL_HOSTNAME_VERIFIER / AllowAllHostnameVerifier, disables hostname checks: "
            "a valid certificate for *any* domain is accepted, so TLS connections can be "
            "intercepted."
        ),
        remediation=(
            "Do not override hostname verification. Remove the custom HostnameVerifier and use "
            "the default (HttpsURLConnection.getDefaultHostnameVerifier() / OkHttp's "
            "OkHostnameVerifier)."
        ),
        references=(
            "https://developer.android.com/privacy-and-security/risks/unsafe-hostname",
            "https://developer.android.com/privacy-and-security/security-ssl#CommonHostnameProbs",
        ),
        cwe="CWE-297",
        masvs="MASVS-NETWORK-1",
    )

    def check(self, ctx: ApkContext) -> Iterable[Finding]:
        for cls, method in iter_methods(ctx):
            if (
                method.name == "verify"
                and HOSTNAME_VERIFIER in cls.interfaces
                and returns_constant(method, 1)
            ):
                yield self.finding(
                    f"{cls.name}.verify() always returns true.",
                    method_location(cls, method),
                    evidence=f"{method.full_name}: return true",
                )
                continue
            for ins in method.instructions:
                ref = ins.ref or ""
                if (
                    ref
                    and any(marker in ref for marker in ALLOW_ALL_MARKERS)
                    and (ins.op.startswith(("sget", "new-instance")))
                ):
                    yield self.finding(
                        f"{method.short_name} uses an allow-all hostname verifier.",
                        method_location(cls, method),
                        evidence=ref,
                    )
                    break
