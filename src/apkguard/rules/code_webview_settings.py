"""AG-CODE-004: insecure WebView configuration."""

from __future__ import annotations

from collections.abc import Iterable

from apkguard.analysis import iter_calls
from apkguard.context import ApkContext
from apkguard.model import Category, Finding, RuleMeta, Severity
from apkguard.rules._util import iter_methods, method_location
from apkguard.rules.base import Rule

WEBSETTINGS = "Landroid/webkit/WebSettings;"
SSL_PROCEED = "Landroid/webkit/SslErrorHandler;->proceed"

# setter name -> (argument value that is insecure, severity, explanation)
INSECURE_SETTERS: dict[str, tuple[int, Severity, str]] = {
    "setAllowUniversalAccessFromFileURLs": (
        1,
        Severity.HIGH,
        "lets JavaScript in file:// pages read any origin, enabling local-file data theft",
    ),
    "setAllowFileAccessFromFileURLs": (
        1,
        Severity.HIGH,
        "lets JavaScript in file:// pages read other local files",
    ),
    "setJavaScriptEnabled": (
        1,
        Severity.INFO,
        "runs JavaScript from loaded pages; make sure only trusted HTTPS content is loaded",
    ),
    "setMixedContentMode": (
        0,  # WebSettings.MIXED_CONTENT_ALWAYS_ALLOW
        Severity.MEDIUM,
        "allows HTTPS pages to load HTTP sub-resources (MIXED_CONTENT_ALWAYS_ALLOW)",
    ),
}


class InsecureWebViewRule(Rule):
    meta = RuleMeta(
        id="AG-CODE-004",
        title="Insecure WebView configuration",
        severity=Severity.HIGH,
        category=Category.CODE,
        description=(
            "Detects WebView settings that weaken the same-origin policy for file:// URLs or "
            "allow mixed content, enabled JavaScript (informational), and "
            "WebViewClient.onReceivedSslError handlers that call "
            "SslErrorHandler.proceed(), which silently accepts invalid TLS certificates and "
            "enables man-in-the-middle attacks."
        ),
        remediation=(
            "Keep setAllowFileAccessFromFileURLs and setAllowUniversalAccessFromFileURLs false "
            "(the default since API 16), use MIXED_CONTENT_NEVER_ALLOW, load local content via "
            "WebViewAssetLoader, and never call handler.proceed() in onReceivedSslError - call "
            "handler.cancel() instead."
        ),
        references=(
            "https://developer.android.com/privacy-and-security/risks/webview-unsafe-file-inclusion",
            "https://developer.android.com/reference/android/webkit/WebViewClient#onReceivedSslError(android.webkit.WebView,%20android.webkit.SslErrorHandler,%20android.net.http.SslError)",
        ),
        cwe="CWE-295",
        masvs="MASVS-PLATFORM-2",
    )

    def check(self, ctx: ApkContext) -> Iterable[Finding]:
        for cls, method in iter_methods(ctx):
            for call in iter_calls(method):
                if call.target_class == WEBSETTINGS and call.target_name in INSECURE_SETTERS:
                    bad_value, severity, why = INSECURE_SETTERS[call.target_name]
                    if call.arg(0) == bad_value:
                        shown = _display(call.target, bad_value)
                        yield self.finding(
                            f"{method.short_name} calls WebSettings.{call.target_name}"
                            f"({shown}), which {why}.",
                            method_location(cls, method),
                            evidence=f"{call.target_name}({shown})",
                            severity=severity,
                        )
                elif method.name == "onReceivedSslError" and call.short_target == SSL_PROCEED:
                    yield self.finding(
                        f"{method.short_name} calls SslErrorHandler.proceed(), accepting "
                        "invalid TLS certificates.",
                        method_location(cls, method),
                        evidence=call.target,
                        severity=Severity.HIGH,
                    )


def _display(target: str, value: int) -> str:
    """Render boolean setter arguments as true/false, everything else as the raw integer."""
    if "(Z)" in target:
        return "true" if value else "false"
    return str(value)
