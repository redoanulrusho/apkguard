"""AG-CODE-007: hardcoded cryptographic keys, IVs and passwords."""

from __future__ import annotations

from collections.abc import Iterable

from apkguard.analysis import BytesConst, iter_calls
from apkguard.context import ApkContext
from apkguard.model import Category, Finding, RuleMeta, Severity
from apkguard.rules._util import iter_methods, method_location
from apkguard.rules.base import Rule

# constructor -> (what the first argument is, severity)
KEY_MATERIAL: dict[str, tuple[str, Severity]] = {
    "Ljavax/crypto/spec/SecretKeySpec;-><init>": ("secret key", Severity.HIGH),
    "Ljavax/crypto/spec/PBEKeySpec;-><init>": ("password", Severity.HIGH),
    "Ljavax/crypto/spec/DESKeySpec;-><init>": ("secret key", Severity.HIGH),
    "Ljavax/crypto/spec/IvParameterSpec;-><init>": ("initialisation vector", Severity.MEDIUM),
    "Ljavax/crypto/spec/GCMParameterSpec;-><init>": ("GCM nonce", Severity.MEDIUM),
}
# For GCMParameterSpec(int tLen, byte[] iv) the IV is the second parameter.
_ARG_INDEX = {"Ljavax/crypto/spec/GCMParameterSpec;-><init>": 1}


class HardcodedKeyRule(Rule):
    meta = RuleMeta(
        id="AG-CODE-007",
        title="Hardcoded cryptographic key or IV",
        severity=Severity.HIGH,
        category=Category.CODE,
        description=(
            "Key material is built from a constant embedded in the app (a string literal "
            "converted with getBytes()/toCharArray()/Base64.decode(), or an array literal). Anyone "
            "can extract it from the APK and decrypt or forge data protected by it. A constant IV "
            "or nonce breaks the security of CBC/GCM encryption."
        ),
        remediation=(
            "Generate keys at runtime and store them in the Android Keystore "
            "(KeyGenParameterSpec), or derive them from user input with a salted KDF. Generate a "
            "fresh random IV/nonce for every encryption with SecureRandom and store it alongside "
            "the ciphertext."
        ),
        references=(
            "https://developer.android.com/privacy-and-security/keystore",
            "https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0013/",
        ),
        cwe="CWE-321",
        masvs="MASVS-CRYPTO-2",
    )

    def check(self, ctx: ApkContext) -> Iterable[Finding]:
        for cls, method in iter_methods(ctx):
            for call in iter_calls(method):
                spec = KEY_MATERIAL.get(call.short_target)
                if spec is None:
                    continue
                value = call.arg(_ARG_INDEX.get(call.short_target, 0))
                if not isinstance(value, BytesConst):
                    continue
                what, severity = spec
                api = call.target_class.rsplit("/", 1)[-1].rstrip(";")
                yield self.finding(
                    f"{method.short_name} creates a {api} from a hardcoded {what}.",
                    method_location(cls, method),
                    evidence=f"new {api}({_redact(value.source)})",
                    severity=severity,
                )


def _redact(source: str) -> str:
    """Avoid printing full secrets in reports: keep the first 4 characters of string literals."""
    if source.startswith('"'):
        end = source.find('"', 1)
        literal = source[1:end] if end > 0 else source[1:]
        rest = source[end + 1 :] if end > 0 else ""
        shown = literal[:4] + "***" if len(literal) > 4 else "***"
        return f'"{shown}"{rest}'
    return source
