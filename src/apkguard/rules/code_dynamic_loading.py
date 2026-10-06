"""AG-CODE-001: dynamic code loading."""

from __future__ import annotations

from collections.abc import Iterable

from apkguard.analysis import iter_calls
from apkguard.context import ApkContext
from apkguard.model import Category, Finding, RuleMeta, Severity
from apkguard.rules._util import iter_methods, method_location
from apkguard.rules.base import Rule

LOADERS: dict[str, Severity] = {
    "Ldalvik/system/DexClassLoader;-><init>": Severity.HIGH,
    "Ldalvik/system/InMemoryDexClassLoader;-><init>": Severity.HIGH,
    "Ldalvik/system/DexFile;->loadDex": Severity.HIGH,
    "Ldalvik/system/DexFile;-><init>": Severity.HIGH,
    "Ldalvik/system/BaseDexClassLoader;-><init>": Severity.MEDIUM,
    "Ldalvik/system/PathClassLoader;-><init>": Severity.MEDIUM,
    "Ldalvik/system/DelegateLastClassLoader;-><init>": Severity.MEDIUM,
}


class DynamicCodeLoadingRule(Rule):
    meta = RuleMeta(
        id="AG-CODE-001",
        title="Dynamic code loading",
        severity=Severity.HIGH,
        category=Category.CODE,
        description=(
            "The app loads Dalvik bytecode at runtime (DexClassLoader, InMemoryDexClassLoader, "
            "DexFile, PathClassLoader). Code that is not part of the signed APK escapes store "
            "review and static analysis; if it is downloaded or stored in a writable location, "
            "an attacker who can replace the file gains code execution in the app."
        ),
        remediation=(
            "Avoid loading code at runtime; use Play Feature Delivery for modular features. If "
            "unavoidable, load only from the app's private, read-only storage, verify a "
            "cryptographic signature of the file before loading, and never load from external "
            "storage or over plain HTTP."
        ),
        references=(
            "https://developer.android.com/privacy-and-security/risks/dynamic-code-loading",
            "https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0026/",
        ),
        cwe="CWE-829",
        masvs="MASVS-CODE-4",
    )

    def check(self, ctx: ApkContext) -> Iterable[Finding]:
        for cls, method in iter_methods(ctx):
            seen: set[str] = set()
            for call in iter_calls(method):
                severity = LOADERS.get(call.short_target)
                if severity is None or call.short_target in seen:
                    continue
                seen.add(call.short_target)
                loader = call.target_class.rsplit("/", 1)[-1].rstrip(";")
                yield self.finding(
                    f"{method.short_name} loads code dynamically via {loader}.",
                    method_location(cls, method),
                    evidence=call.target,
                    severity=severity,
                )
