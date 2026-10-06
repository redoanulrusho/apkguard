from __future__ import annotations

import pytest

from apkguard.model import Severity
from apkguard.rules.code_dynamic_loading import DynamicCodeLoadingRule
from apkguard.rules.code_hardcoded_key import HardcodedKeyRule
from apkguard.rules.code_hostname_verifier import InsecureHostnameVerifierRule
from apkguard.rules.code_reflection import ReflectionRule
from apkguard.rules.code_trustmanager import InsecureTrustManagerRule
from apkguard.rules.code_weak_cipher import WeakCipherRule, classify
from apkguard.rules.code_weak_hash import WeakHashRule
from apkguard.rules.code_webview_bridge import WebViewJavascriptInterfaceRule
from apkguard.rules.code_webview_settings import InsecureWebViewRule

from helpers import (
    const,
    const_string,
    ctx,
    fill_array,
    invoke,
    klass,
    manifest,
    method,
    move_result,
    new_array,
    new_instance,
    ret,
    ret_void,
    run,
    sget,
    single_method_class,
)

APP = "Lcom/example/app/Main;"
CIPHER = "Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;"
DIGEST = (
    "Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;"
)
GET_BYTES = "Ljava/lang/String;->getBytes()[B"
KEYSPEC_INIT = "Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V"
IV_INIT = "Ljavax/crypto/spec/IvParameterSpec;-><init>([B)V"


def code_ctx(*instructions, cls: str = APP, **kw):  # type: ignore[no-untyped-def]
    return ctx(classes=[single_method_class(cls, *instructions)], **kw)


# --- AG-CODE-001 dynamic code loading --------------------------------------------------------


def test_dex_class_loader_is_reported() -> None:
    c = code_ctx(
        new_instance(0, "Ldalvik/system/DexClassLoader;"),
        invoke(
            "Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;Ljava/lang/String;"
            "Ljava/lang/String;Ljava/lang/ClassLoader;)V",
            0, 1, 2, 3, 4, kind="direct",
        ),
    )  # fmt: skip
    findings = run(DynamicCodeLoadingRule(), c)
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert findings[0].location.symbol == f"{APP}->run"
    assert "DexClassLoader" in findings[0].message


def test_path_class_loader_is_medium() -> None:
    c = code_ctx(
        invoke(
            "Ldalvik/system/PathClassLoader;-><init>(Ljava/lang/String;Ljava/lang/ClassLoader;)V",
            0,
            1,
            2,
            kind="direct",
        )
    )
    assert [f.severity for f in run(DynamicCodeLoadingRule(), c)] == [Severity.MEDIUM]


def test_no_dynamic_loading_is_clean() -> None:
    c = code_ctx(
        invoke("Ljava/lang/ClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;", 0, 1)
    )
    assert run(DynamicCodeLoadingRule(), c) == []


def test_excluded_package_is_skipped() -> None:
    c = code_ctx(
        invoke("Ldalvik/system/DexClassLoader;-><init>()V", 0, kind="direct"),
        cls="Lcom/vendor/sdk/Loader;",
        exclude_packages=("Lcom/vendor/",),
    )
    assert run(DynamicCodeLoadingRule(), c) == []


# --- AG-CODE-002 reflection ------------------------------------------------------------------

FOR_NAME = "Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;"
INVOKE = (
    "Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;"
)


def test_reflection_heavy_class_is_reported() -> None:
    instructions = []
    for _ in range(4):
        instructions += [invoke(FOR_NAME, 1, kind="static"), invoke(INVOKE, 2, 3, 4)]
    findings = run(ReflectionRule(), code_ctx(*instructions))
    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW
    assert "8 reflective calls" in findings[0].message
    assert "4 with non-constant names" in findings[0].message


def test_reflection_below_threshold_is_clean() -> None:
    c = code_ctx(const_string(1, "java.util.ArrayList"), invoke(FOR_NAME, 1, kind="static"))
    assert run(ReflectionRule(), c) == []


def test_reflection_threshold_is_configurable() -> None:
    c = code_ctx(invoke(FOR_NAME, 1, kind="static"), invoke(INVOKE, 2, 3, 4))
    assert len(run(ReflectionRule({"threshold": 2}), c)) == 1


def test_reflection_to_hidden_api_is_reported() -> None:
    c = code_ctx(const_string(1, "android.app.ActivityThread"), invoke(FOR_NAME, 1, kind="static"))
    findings = run(ReflectionRule(), c)
    assert [f.severity for f in findings] == [Severity.LOW]
    assert "android.app.ActivityThread" in findings[0].message


# --- AG-CODE-003 addJavascriptInterface ------------------------------------------------------

ADD_JS = "Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V"


def test_add_javascript_interface_is_reported_with_name() -> None:
    c = code_ctx(const_string(2, "Android"), invoke(ADD_JS, 0, 1, 2))
    findings = run(WebViewJavascriptInterfaceRule(), c)
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert '"Android"' in findings[0].message


def test_add_javascript_interface_with_low_min_sdk_is_high() -> None:
    c = code_ctx(invoke(ADD_JS, 0, 1, 2))
    c.manifest = manifest(min_sdk=16)
    findings = run(WebViewJavascriptInterfaceRule(), c)
    assert findings[0].severity is Severity.HIGH


def test_webview_subclass_call_is_detected() -> None:
    target = ADD_JS.replace("Landroid/webkit/WebView;", "Lcom/example/MyWebView;")
    assert len(run(WebViewJavascriptInterfaceRule(), code_ctx(invoke(target, 0, 1, 2)))) == 1


def test_unrelated_method_named_similarly_is_clean() -> None:
    c = code_ctx(invoke("Lcom/x/Y;->addJavascriptInterface(I)V", 0, 1))
    assert run(WebViewJavascriptInterfaceRule(), c) == []


# --- AG-CODE-004 insecure WebView settings ---------------------------------------------------

UNIVERSAL = "Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V"
MIXED = "Landroid/webkit/WebSettings;->setMixedContentMode(I)V"


def test_universal_file_access_true_is_high() -> None:
    findings = run(InsecureWebViewRule(), code_ctx(const(1, 1), invoke(UNIVERSAL, 0, 1)))
    assert [f.severity for f in findings] == [Severity.HIGH]


def test_universal_file_access_false_is_clean() -> None:
    assert run(InsecureWebViewRule(), code_ctx(const(1, 0), invoke(UNIVERSAL, 0, 1))) == []


def test_javascript_enabled_is_info() -> None:
    target = "Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V"
    findings = run(InsecureWebViewRule(), code_ctx(const(1, 1), invoke(target, 0, 1)))
    assert [f.severity for f in findings] == [Severity.INFO]


def test_mixed_content_always_allow_is_medium() -> None:
    findings = run(InsecureWebViewRule(), code_ctx(const(1, 0), invoke(MIXED, 0, 1)))
    assert [f.severity for f in findings] == [Severity.MEDIUM]


def test_mixed_content_never_allow_is_clean() -> None:
    assert run(InsecureWebViewRule(), code_ctx(const(1, 1), invoke(MIXED, 0, 1))) == []


def test_ssl_error_proceed_is_high() -> None:
    cls = klass(
        "Lcom/example/Client;",
        method(
            "Lcom/example/Client;",
            "onReceivedSslError",
            invoke("Landroid/webkit/SslErrorHandler;->proceed()V", 2),
            ret_void(),
        ),
        superclass="Landroid/webkit/WebViewClient;",
    )
    findings = run(InsecureWebViewRule(), ctx(classes=[cls]))
    assert len(findings) == 1
    assert "proceed" in findings[0].message


def test_ssl_error_cancel_is_clean() -> None:
    cls = klass(
        "Lcom/example/Client;",
        method(
            "Lcom/example/Client;",
            "onReceivedSslError",
            invoke("Landroid/webkit/SslErrorHandler;->cancel()V", 2),
        ),
    )
    assert run(InsecureWebViewRule(), ctx(classes=[cls])) == []


# --- AG-CODE-005 weak ciphers ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("transformation", "severity"),
    [
        ("AES/ECB/PKCS5Padding", Severity.MEDIUM),
        ("AES", Severity.MEDIUM),
        ("DES/CBC/PKCS5Padding", Severity.HIGH),
        ("DESede/CBC/PKCS5Padding", Severity.HIGH),
        ("RC4", Severity.HIGH),
        ("RSA/ECB/NoPadding", Severity.MEDIUM),
    ],
)
def test_weak_transformations(transformation: str, severity: Severity) -> None:
    result = classify(transformation)
    assert result is not None
    assert result[0] is severity


@pytest.mark.parametrize(
    "transformation",
    ["AES/GCM/NoPadding", "AES/CBC/PKCS5Padding", "RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
     "RSA/ECB/PKCS1Padding", "ChaCha20-Poly1305"],
)  # fmt: skip
def test_strong_transformations(transformation: str) -> None:
    assert classify(transformation) is None


def test_weak_cipher_rule_reports_call_site() -> None:
    c = code_ctx(const_string(0, "AES/ECB/PKCS5Padding"), invoke(CIPHER, 0, kind="static"))
    findings = run(WeakCipherRule(), c)
    assert len(findings) == 1
    assert findings[0].evidence == 'Cipher.getInstance("AES/ECB/PKCS5Padding")'


def test_weak_cipher_rule_ignores_non_constant_argument() -> None:
    assert run(WeakCipherRule(), code_ctx(invoke(CIPHER, 0, kind="static"))) == []


def test_weak_cipher_rule_tracks_register_overwrite() -> None:
    c = code_ctx(
        const_string(0, "AES/ECB/PKCS5Padding"),
        const_string(0, "AES/GCM/NoPadding"),
        invoke(CIPHER, 0, kind="static"),
    )
    assert run(WeakCipherRule(), c) == []


# --- AG-CODE-006 weak hashes -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("algo", "severity"),
    [("MD5", Severity.MEDIUM), ("SHA-1", Severity.LOW), ("md5", Severity.MEDIUM)],
)
def test_weak_hash_reported(algo: str, severity: Severity) -> None:
    c = code_ctx(const_string(0, algo), invoke(DIGEST, 0, kind="static"))
    findings = run(WeakHashRule(), c)
    assert [f.severity for f in findings] == [severity]


def test_strong_hash_is_clean() -> None:
    c = code_ctx(const_string(0, "SHA-256"), invoke(DIGEST, 0, kind="static"))
    assert run(WeakHashRule(), c) == []


def test_hmac_md5_is_low() -> None:
    c = code_ctx(
        const_string(0, "HmacMD5"),
        invoke(
            "Ljavax/crypto/Mac;->getInstance(Ljava/lang/String;)Ljavax/crypto/Mac;",
            0,
            kind="static",
        ),
    )
    assert [f.severity for f in run(WeakHashRule(), c)] == [Severity.LOW]


# --- AG-CODE-007 hardcoded keys --------------------------------------------------------------


def test_secret_key_from_string_literal_is_high() -> None:
    c = code_ctx(
        const_string(1, "SuperSecretKey12"),
        invoke(GET_BYTES, 1),
        move_result(1),
        const_string(2, "AES"),
        new_instance(0, "Ljavax/crypto/spec/SecretKeySpec;"),
        invoke(KEYSPEC_INIT, 0, 1, 2, kind="direct"),
    )
    findings = run(HardcodedKeyRule(), c)
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    # The full secret must not be echoed in reports.
    assert "SuperSecretKey12" not in (findings[0].evidence or "")
    assert "Supe***" in (findings[0].evidence or "")


def test_iv_from_array_literal_is_medium() -> None:
    c = code_ctx(
        const(1, 16),
        new_array(2, 1),
        fill_array(2),
        new_instance(0, "Ljavax/crypto/spec/IvParameterSpec;"),
        invoke(IV_INIT, 0, 2, kind="direct"),
    )
    assert [f.severity for f in run(HardcodedKeyRule(), c)] == [Severity.MEDIUM]


def test_key_from_runtime_bytes_is_clean() -> None:
    c = code_ctx(
        invoke("Ljava/security/SecureRandom;->nextBytes([B)V", 3, 1),
        const_string(2, "AES"),
        invoke(KEYSPEC_INIT, 0, 1, 2, kind="direct"),
    )
    assert run(HardcodedKeyRule(), c) == []


def test_key_from_base64_literal_is_high() -> None:
    c = code_ctx(
        const_string(1, "c2VjcmV0a2V5MTIzNDU2Nw=="),
        const(3, 0),
        invoke("Landroid/util/Base64;->decode(Ljava/lang/String;I)[B", 1, 3, kind="static"),
        move_result(1),
        invoke(KEYSPEC_INIT, 0, 1, 2, kind="direct"),
    )
    assert len(run(HardcodedKeyRule(), c)) == 1


# --- AG-CODE-008 TrustManager ----------------------------------------------------------------

TM = "Ljavax/net/ssl/X509TrustManager;"


def _trust_manager(*body):  # type: ignore[no-untyped-def]
    name = "Lcom/example/TrustAll;"
    return klass(
        name,
        method(name, "checkClientTrusted", ret_void()),
        method(name, "checkServerTrusted", *body),
        method(name, "getAcceptedIssuers", const(0, 0), ret(0)),
        interfaces=[TM],
    )


def test_empty_check_server_trusted_is_high() -> None:
    findings = run(InsecureTrustManagerRule(), ctx(classes=[_trust_manager(ret_void())]))
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert findings[0].location.symbol == "Lcom/example/TrustAll;->checkServerTrusted"


def test_validating_trust_manager_is_clean() -> None:
    body = (
        invoke(
            "Ljavax/net/ssl/X509TrustManager;->checkServerTrusted([Ljava/security/cert/"
            "X509Certificate;Ljava/lang/String;)V",
            3,
            1,
            2,
            kind="interface",
        ),
        ret_void(),
    )
    assert run(InsecureTrustManagerRule(), ctx(classes=[_trust_manager(*body)])) == []


def test_empty_method_in_unrelated_class_is_clean() -> None:
    cls = klass(
        "Lcom/example/Other;", method("Lcom/example/Other;", "checkServerTrusted", ret_void())
    )
    assert run(InsecureTrustManagerRule(), ctx(classes=[cls])) == []


# --- AG-CODE-009 HostnameVerifier ------------------------------------------------------------

HV = "Ljavax/net/ssl/HostnameVerifier;"


def _verifier(*body):  # type: ignore[no-untyped-def]
    name = "Lcom/example/AllowAll;"
    return klass(name, method(name, "verify", *body), interfaces=[HV])


def test_verify_returning_true_is_high() -> None:
    findings = run(InsecureHostnameVerifierRule(), ctx(classes=[_verifier(const(0, 1), ret(0))]))
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH


def test_verify_returning_false_is_clean() -> None:
    assert run(InsecureHostnameVerifierRule(), ctx(classes=[_verifier(const(0, 0), ret(0))])) == []


def test_verify_with_real_logic_is_clean() -> None:
    body = (
        invoke(
            "Ljavax/net/ssl/HostnameVerifier;->verify(Ljava/lang/String;"
            "Ljavax/net/ssl/SSLSession;)Z",
            3,
            1,
            2,
            kind="interface",
        ),
        move_result(0),
        ret(0),
    )
    assert run(InsecureHostnameVerifierRule(), ctx(classes=[_verifier(*body)])) == []


def test_allow_all_hostname_verifier_field_is_reported() -> None:
    c = code_ctx(
        sget(
            0,
            "Lorg/apache/http/conn/ssl/SSLSocketFactory;->ALLOW_ALL_HOSTNAME_VERIFIER"
            "Lorg/apache/http/conn/ssl/X509HostnameVerifier;",
        ),
        invoke(
            "Lorg/apache/http/conn/ssl/SSLSocketFactory;->setHostnameVerifier("
            "Lorg/apache/http/conn/ssl/X509HostnameVerifier;)V",
            1,
            0,
        ),
    )
    findings = run(InsecureHostnameVerifierRule(), c)
    assert len(findings) == 1
    assert "allow-all" in findings[0].message
