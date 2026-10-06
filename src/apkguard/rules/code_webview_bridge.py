"""AG-CODE-003: WebView JavaScript interface (addJavascriptInterface)."""

from __future__ import annotations

from collections.abc import Iterable

from apkguard.analysis import StrConst, iter_calls
from apkguard.context import ApkContext
from apkguard.model import Category, Finding, RuleMeta, Severity
from apkguard.rules._util import iter_methods, method_location
from apkguard.rules.base import Rule


class WebViewJavascriptInterfaceRule(Rule):
    meta = RuleMeta(
        id="AG-CODE-003",
        title="WebView JavaScript interface exposed",
        severity=Severity.MEDIUM,
        category=Category.CODE,
        description=(
            "WebView.addJavascriptInterface exposes Java objects to JavaScript running in the "
            "page. Any script that runs in that WebView - including injected or third-party "
            "content, or content loaded over HTTP - can call the exposed methods. On API level "
            "< 17 every public method (including getClass()) is reachable, which leads to remote "
            "code execution."
        ),
        remediation=(
            "Load only trusted, HTTPS content in WebViews that have a JavaScript interface. "
            "Expose a minimal object whose methods are annotated with @JavascriptInterface, "
            "validate all arguments, and consider WebViewCompat.addWebMessageListener with an "
            "origin allow-list instead. Set minSdkVersion >= 17."
        ),
        references=(
            "https://developer.android.com/privacy-and-security/risks/insecure-webview-native-bridges",
            "https://developer.android.com/reference/android/webkit/WebView#addJavascriptInterface(java.lang.Object,%20java.lang.String)",
        ),
        cwe="CWE-749",
        masvs="MASVS-PLATFORM-2",
    )

    def check(self, ctx: ApkContext) -> Iterable[Finding]:
        min_sdk = ctx.manifest.min_sdk or 1
        severity = Severity.HIGH if min_sdk < 17 else self.meta.severity
        for cls, method in iter_methods(ctx):
            for call in iter_calls(method):
                if call.target_name != "addJavascriptInterface":
                    continue
                if "(Ljava/lang/Object;Ljava/lang/String;)" not in call.target:
                    continue
                name = call.arg(1)
                js_name = f' as "{name.value}"' if isinstance(name, StrConst) else ""
                note = ""
                if min_sdk < 17:
                    note = " minSdkVersion < 17 makes this exploitable for code execution."
                yield self.finding(
                    f"{method.short_name} exposes a Java object to JavaScript{js_name}.{note}",
                    method_location(cls, method),
                    evidence=call.target,
                    severity=severity,
                )
