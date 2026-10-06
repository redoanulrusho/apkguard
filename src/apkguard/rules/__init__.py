"""Rule registry. Each rule lives in its own module; add new rules to :data:`ALL_RULES`."""

from __future__ import annotations

from apkguard.rules.base import Rule
from apkguard.rules.code_dynamic_loading import DynamicCodeLoadingRule
from apkguard.rules.code_hardcoded_key import HardcodedKeyRule
from apkguard.rules.code_hostname_verifier import InsecureHostnameVerifierRule
from apkguard.rules.code_reflection import ReflectionRule
from apkguard.rules.code_trustmanager import InsecureTrustManagerRule
from apkguard.rules.code_weak_cipher import WeakCipherRule
from apkguard.rules.code_weak_hash import WeakHashRule
from apkguard.rules.code_webview_bridge import WebViewJavascriptInterfaceRule
from apkguard.rules.code_webview_settings import InsecureWebViewRule
from apkguard.rules.manifest_backup import AllowBackupRule
from apkguard.rules.manifest_cleartext import CleartextTrafficRule
from apkguard.rules.manifest_debuggable import DebuggableRule
from apkguard.rules.manifest_exported import ExportedComponentRule
from apkguard.rules.manifest_sdk import OutdatedSdkRule
from apkguard.rules.permissions_combinations import SuspiciousPermissionCombinationRule
from apkguard.rules.permissions_dangerous import DangerousPermissionsRule
from apkguard.rules.secrets_hardcoded import HardcodedSecretRule

ALL_RULES: tuple[type[Rule], ...] = (
    DebuggableRule,
    AllowBackupRule,
    CleartextTrafficRule,
    ExportedComponentRule,
    OutdatedSdkRule,
    DangerousPermissionsRule,
    SuspiciousPermissionCombinationRule,
    DynamicCodeLoadingRule,
    ReflectionRule,
    WebViewJavascriptInterfaceRule,
    InsecureWebViewRule,
    WeakCipherRule,
    WeakHashRule,
    HardcodedKeyRule,
    InsecureTrustManagerRule,
    InsecureHostnameVerifierRule,
    HardcodedSecretRule,
)

RULES_BY_ID: dict[str, type[Rule]] = {rule.meta.id: rule for rule in ALL_RULES}

__all__ = ["ALL_RULES", "RULES_BY_ID", "Rule"]
