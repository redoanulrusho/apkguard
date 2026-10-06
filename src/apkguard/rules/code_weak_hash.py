"""AG-CODE-006: weak hash algorithms."""

from __future__ import annotations

from collections.abc import Iterable

from apkguard.analysis import StrConst, iter_calls
from apkguard.context import ApkContext
from apkguard.model import Category, Finding, RuleMeta, Severity
from apkguard.rules._util import iter_methods, method_location
from apkguard.rules.base import Rule

FACTORIES = {
    "Ljava/security/MessageDigest;->getInstance": "MessageDigest",
    "Ljavax/crypto/Mac;->getInstance": "Mac",
}
WEAK: dict[str, Severity] = {
    "MD2": Severity.MEDIUM,
    "MD4": Severity.MEDIUM,
    "MD5": Severity.MEDIUM,
    "SHA1": Severity.LOW,
    "SHA-1": Severity.LOW,
    "SHA": Severity.LOW,
    "HMACMD5": Severity.LOW,
}


class WeakHashRule(Rule):
    meta = RuleMeta(
        id="AG-CODE-006",
        title="Weak hash algorithm",
        severity=Severity.MEDIUM,
        category=Category.CODE,
        description=(
            "MD5, MD4, MD2 and SHA-1 are vulnerable to collision attacks and must not be used for "
            "signatures, integrity protection of untrusted data, or password hashing. Usage for "
            "non-security purposes (cache keys, checksums) is acceptable but should be confirmed."
        ),
        remediation=(
            "Use SHA-256 or stronger for integrity, HMAC-SHA256 for message authentication, and a "
            "dedicated password hashing function (Argon2, scrypt, PBKDF2 with a high iteration "
            "count) for passwords. Suppress the finding if the usage is not security relevant."
        ),
        references=(
            "https://developer.android.com/privacy-and-security/cryptography#deprecated-functionality",
            "https://cwe.mitre.org/data/definitions/328.html",
        ),
        cwe="CWE-328",
        masvs="MASVS-CRYPTO-1",
    )

    def check(self, ctx: ApkContext) -> Iterable[Finding]:
        for cls, method in iter_methods(ctx):
            seen: set[str] = set()
            for call in iter_calls(method):
                api = FACTORIES.get(call.short_target)
                if api is None:
                    continue
                algo = call.arg(0)
                if not isinstance(algo, StrConst):
                    continue
                severity = WEAK.get(algo.value.upper())
                if severity is None or algo.value in seen:
                    continue
                seen.add(algo.value)
                yield self.finding(
                    f'{method.short_name} uses {api}.getInstance("{algo.value}").',
                    method_location(cls, method),
                    evidence=f'{api}.getInstance("{algo.value}")',
                    severity=severity,
                )
