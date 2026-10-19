"""Recognise findings that come from well-known third-party libraries.

Most Android apps bundle large libraries (AndroidX, Kotlin, Google Play services, OkHttp, ...).
Code rules fire inside them too, but the app developer cannot fix that code, so those findings
are noise in an app-focused report. This module decides, per finding, whether its code lives in
a known library package. The scanner then separates (default), includes or drops those findings
according to :class:`LibraryMode`.

Only findings that point at a class are classified: code findings (``classes*.dex``, symbol in
smali form ``Lcom/foo/Bar;->method``) and manifest component findings (symbol is a dotted class
name such as ``androidx.work.impl.WorkManagerInitializer``). Other manifest findings
(permissions, ``<application>`` attributes) always belong to the app.
"""

from __future__ import annotations

from enum import Enum

from apkguard.model import Finding

#: Package prefixes of common third-party libraries, as dotted Java package names.
#: Matching is on whole package segments, so ``kotlin`` matches ``kotlin.io`` but not
#: ``kotlinapp``. Extend it per project with ``library_packages`` in the config file.
DEFAULT_LIBRARY_PACKAGES: tuple[str, ...] = (
    # Android / Google
    "android.support",
    "androidx",
    "com.google",
    # Kotlin and JetBrains
    "kotlin",
    "kotlinx",
    "org.jetbrains",
    "org.intellij",
    # Networking, serialisation, DI, images, reactive
    "okhttp3",
    "okio",
    "retrofit2",
    "com.squareup",
    "com.fasterxml.jackson",
    "dagger",
    "javax.inject",
    "hilt_aggregated_deps",
    "com.bumptech.glide",
    "coil",
    "io.coil_kt",
    "io.reactivex",
    "org.reactivestreams",
    # Common Java libraries
    "org.apache",
    "org.bouncycastle",
    "org.slf4j",
    "org.osmdroid",
    "org.greenrobot",
    "net.zetetic",
    "io.ktor",
    "com.journeyapps",
    "org.acra",
    # Cross-platform frameworks and other SDKs commonly bundled whole
    "com.getcapacitor",
    "io.flutter",
    "com.facebook",
    "com.sun",
    "org.xbill",
)


class LibraryMode(str, Enum):
    """What to do with findings located in third-party library code."""

    #: Keep them in reports, marked as library findings, but hide them from the terminal table
    #: and never let them fail the build. This is the default.
    SEPARATE = "separate"
    #: Treat them exactly like findings in app code.
    INCLUDE = "include"
    #: Drop them from the results entirely.
    EXCLUDE = "exclude"


def class_name_of(finding: Finding) -> str | None:
    """Dotted class name a finding points at, or ``None`` if it is not about a class."""
    symbol = finding.location.symbol
    if not symbol:
        return None
    if finding.location.file.endswith(".dex"):
        # Smali form: "Lcom/foo/Bar;->method" or "Lcom/foo/Bar;"
        type_name = symbol.split("->", 1)[0]
        if type_name.startswith("L") and type_name.endswith(";"):
            return type_name[1:-1].replace("/", ".")
        return None
    component = finding.extra.get("component")
    return component if isinstance(component, str) else None


def _in_package(class_name: str, package: str) -> bool:
    return class_name == package or class_name.startswith(package + ".")


def match_library(
    class_name: str, library_packages: tuple[str, ...], app_package: str = ""
) -> str | None:
    """Return the library package ``class_name`` belongs to, or ``None`` for app code.

    Code inside the app's own package is never treated as a library, even when the app's
    package itself starts with a library prefix (e.g. an app named ``com.google.zxing.client``).
    The longest matching prefix wins, so reports name the most specific library.
    """
    if app_package and _in_package(class_name, app_package):
        return None
    matches = [pkg for pkg in library_packages if _in_package(class_name, pkg)]
    return max(matches, key=len) if matches else None


def tag_library_findings(
    findings: list[Finding], library_packages: tuple[str, ...], app_package: str
) -> None:
    """Set :attr:`Finding.library` on every finding located in library code."""
    for finding in findings:
        class_name = class_name_of(finding)
        if class_name is not None:
            finding.library = match_library(class_name, library_packages, app_package)
