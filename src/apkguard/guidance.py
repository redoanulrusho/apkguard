"""Triage guidance per rule: how to confirm a finding and when it is usually not a problem.

Rule metadata (:class:`~apkguard.model.RuleMeta`) says *what* a rule detects and how to fix it.
This module adds what a reviewer needs to decide whether a specific finding matters. The notes
come from the manual review in EVALUATION.md, where most non-actionable findings fell into a
few recurring patterns (library code, conditions the analysis ignores, intended behaviour).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Triage:
    #: Concrete steps to confirm the finding in the app.
    verify: str
    #: Common situations in which the finding is correct but not a vulnerability.
    usually_benign_when: str


TRIAGE: dict[str, Triage] = {
    "AG-MAN-001": Triage(
        verify="Check the release build's merged manifest for android:debuggable; release "
        "builds from Gradle are not debuggable unless the build type sets it.",
        usually_benign_when="The scanned APK is a debug build that is never distributed.",
    ),
    "AG-MAN-002": Triage(
        verify="List what the app stores (databases, shared preferences, files) and whether "
        "backup rules exclude tokens, keys or personal data.",
        usually_benign_when="The app stores no credentials or personal data, or backup rules "
        "already exclude them.",
    ),
    "AG-MAN-003": Triage(
        verify="Find which hosts are contacted over http:// and whether any credentials or "
        "personal data travel over them.",
        usually_benign_when="The app is a client for user-hosted servers on a local network "
        "(by design), or cleartext is limited to specific domains in the network security "
        "config.",
    ),
    "AG-MAN-004": Triage(
        verify="Read the component's onCreate/onReceive/onBind/query/openFile code and check "
        "what an arbitrary app can trigger or read with a crafted Intent or URI.",
        usually_benign_when="The system must reach it (sync adapters, account authenticators, "
        "media button receivers, widgets), or it only exposes public data. Library components "
        "are reported separately by default.",
    ),
    "AG-MAN-005": Triage(
        verify="Compare targetSdkVersion with the current Google Play requirement and check "
        "which platform protections the old level opts out of.",
        usually_benign_when="minSdk is low on purpose to support old devices; that is a "
        "product decision more than a vulnerability.",
    ),
    "AG-PERM-001": Triage(
        verify="Map each permission to the feature that needs it and check that it is requested "
        "at runtime only when that feature is used.",
        usually_benign_when="The permission is central to the app's purpose (a launcher using "
        "accessibility, a camera app using CAMERA).",
    ),
    "AG-PERM-002": Triage(
        verify="Check where the collected data goes: which servers, whether it is encrypted, "
        "and whether the privacy policy discloses it.",
        usually_benign_when="The combination is the app's core feature (an email client with "
        "contacts, a location sharing app with background location).",
    ),
    "AG-CODE-001": Triage(
        verify="Find where the loaded file comes from. Code loaded from app-private storage "
        "that was extracted from the APK itself is far less risky than downloaded code.",
        usually_benign_when="It is AndroidX MultiDex or a similar library loading the app's "
        "own secondary DEX files (often visible as obfuscated classes).",
    ),
    "AG-CODE-002": Triage(
        verify="Look at the reflected names: constant names of known classes are normal, names "
        "built at runtime or decrypted strings are suspicious.",
        usually_benign_when="All names are constants (the message reports how many are not), "
        "or the class belongs to AndroidX, Kotlin or another library, including R8-renamed "
        "library classes.",
    ),
    "AG-CODE-003": Triage(
        verify="List the @JavascriptInterface methods of the exposed object and check which "
        "pages the WebView can load. Remote or user-controlled content is the risk.",
        usually_benign_when="The WebView only loads bundled assets from the APK.",
    ),
    "AG-CODE-004": Triage(
        verify="Check whether the flagged call is reachable in a release build. The analysis "
        "ignores conditions, so look for guards such as a debuggable check or a preference.",
        usually_benign_when="The call is behind a debug-only or opt-in condition (seen in "
        "Cordova), or it is setJavaScriptEnabled for bundled content (reported as info).",
    ),
    "AG-CODE-005": Triage(
        verify="Find what the cipher protects and whether the algorithm is dictated by a "
        "protocol or file format.",
        usually_benign_when="A protocol mandates it for compatibility (DES in NTLM inside "
        "JavaMail) and the data is protected by an outer TLS layer.",
    ),
    "AG-CODE-006": Triage(
        verify="Find what the hash is used for: passwords, signatures or integrity checks are "
        "security uses; cache keys and file names are not.",
        usually_benign_when="It names cache files, de-duplicates data or implements a protocol "
        "that requires it (DNSSEC, HTTP digest).",
    ),
    "AG-CODE-007": Triage(
        verify="Confirm the key bytes are really a literal in the APK (decompile the method), "
        "and find what data the key protects.",
        usually_benign_when="The 'key' only obfuscates non-sensitive data, or the value is a "
        "public test vector.",
    ),
    "AG-CODE-008": Triage(
        verify="Find where the TrustManager is installed (SSLContext.init) and whether that "
        "code path is used for real connections or only behind an explicit user opt-in.",
        usually_benign_when="It is unused library code (for example a BouncyCastle helper) or "
        "an opt-in 'accept self-signed certificate' feature limited to one host.",
    ),
    "AG-CODE-009": Triage(
        verify="Find which connections use this verifier and whether it is limited to "
        "user-approved hosts.",
        usually_benign_when="It is an explicit, per-server user opt-in for self-hosted servers "
        "with self-signed certificates.",
    ),
    "AG-SEC-001": Triage(
        verify="Identify the service the value belongs to and what it allows. Keys that are "
        "designed to be public (Firebase/Google API keys restricted by package) are low risk.",
        usually_benign_when="The key is public by design and restricted on the provider side, "
        "or it is a placeholder or test value.",
    ),
}


def triage_for(rule_id: str) -> Triage | None:
    return TRIAGE.get(rule_id)
