"""AG-CODE-005: weak cipher algorithms and modes."""

from __future__ import annotations

from collections.abc import Iterable

from apkguard.analysis import StrConst, iter_calls
from apkguard.context import ApkContext
from apkguard.model import Category, Finding, RuleMeta, Severity
from apkguard.rules._util import iter_methods, method_location
from apkguard.rules.base import Rule

CIPHER_GET_INSTANCE = "Ljavax/crypto/Cipher;->getInstance"
BROKEN_ALGORITHMS = {
    "DES",
    "DESEDE",
    "TRIPLEDES",
    "3DES",
    "RC4",
    "ARC4",
    "ARCFOUR",
    "RC2",
    "BLOWFISH",
}
# Block ciphers for which "no mode" means the provider default, which is ECB.
BLOCK_CIPHERS = {"AES", "DES", "DESEDE", "BLOWFISH", "RC2"}


def classify(transformation: str) -> tuple[Severity, str] | None:
    """Return (severity, reason) if ``transformation`` (e.g. ``AES/ECB/PKCS5Padding``) is weak."""
    parts = [p.strip().upper() for p in transformation.split("/")]
    algorithm = parts[0]
    mode = parts[1] if len(parts) > 1 else None
    padding = parts[2] if len(parts) > 2 else None
    if algorithm in BROKEN_ALGORITHMS:
        return Severity.HIGH, f"{parts[0]} is a broken or deprecated cipher"
    if algorithm == "RSA":
        if padding == "NOPADDING":
            return Severity.MEDIUM, "RSA without padding (textbook RSA) is insecure"
        return None  # "RSA/ECB/..." is the standard JCA name; ECB is meaningless for RSA
    if mode == "ECB":
        return Severity.MEDIUM, "ECB mode leaks patterns in the plaintext"
    if mode is None and algorithm in BLOCK_CIPHERS:
        return Severity.MEDIUM, f'"{transformation}" without a mode defaults to ECB'
    return None


class WeakCipherRule(Rule):
    meta = RuleMeta(
        id="AG-CODE-005",
        title="Weak cipher or cipher mode",
        severity=Severity.MEDIUM,
        category=Category.CODE,
        description=(
            "Cipher.getInstance is called with a broken algorithm (DES, 3DES, RC4, Blowfish, RC2), "
            'with ECB mode, with a bare block-cipher name such as "AES" (which defaults to '
            "ECB), or with unpadded RSA. These do not provide confidentiality against a capable "
            "attacker."
        ),
        remediation=(
            'Use authenticated encryption: "AES/GCM/NoPadding" with a random 12-byte IV per '
            "message (or ChaCha20-Poly1305), and RSA only with OAEP padding. Consider Google Tink "
            "or Jetpack Security, which choose safe parameters for you."
        ),
        references=(
            "https://developer.android.com/privacy-and-security/cryptography",
            "https://developer.android.com/privacy-and-security/risks/weak-prng",
            "https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0013/",
        ),
        cwe="CWE-327",
        masvs="MASVS-CRYPTO-1",
    )

    def check(self, ctx: ApkContext) -> Iterable[Finding]:
        for cls, method in iter_methods(ctx):
            seen: set[str] = set()
            for call in iter_calls(method):
                if call.short_target != CIPHER_GET_INSTANCE:
                    continue
                transformation = call.arg(0)
                if not isinstance(transformation, StrConst) or transformation.value in seen:
                    continue
                result = classify(transformation.value)
                if result is None:
                    continue
                seen.add(transformation.value)
                severity, reason = result
                yield self.finding(
                    f'{method.short_name} uses Cipher.getInstance("{transformation.value}"): '
                    f"{reason}.",
                    method_location(cls, method),
                    evidence=f'Cipher.getInstance("{transformation.value}")',
                    severity=severity,
                )
