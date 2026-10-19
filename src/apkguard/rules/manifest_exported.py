"""AG-MAN-004: exported components that are not protected by a permission."""

from __future__ import annotations

from collections.abc import Iterable

from apkguard.context import ApkContext, Component, android_attr
from apkguard.model import Category, Finding, Location, RuleMeta, Severity
from apkguard.rules.base import Rule

MANIFEST = "AndroidManifest.xml"

_SEVERITY_BY_TAG = {
    "provider": Severity.HIGH,
    "service": Severity.MEDIUM,
    "receiver": Severity.MEDIUM,
    "activity": Severity.LOW,
    "activity-alias": Severity.LOW,
}

# Protection levels that do not meaningfully restrict which apps can obtain a permission.
_WEAK_PROTECTION = {"normal", "dangerous", "0x0", "0x1", "0", "1"}


class ExportedComponentRule(Rule):
    meta = RuleMeta(
        id="AG-MAN-004",
        title="Exported component without permission",
        severity=Severity.MEDIUM,
        category=Category.MANIFEST,
        description=(
            "An activity, service, broadcast receiver or content provider can be started or "
            "queried by any other app on the device, and no permission restricts access. "
            'Components are exported explicitly (android:exported="true") or, for apps that '
            "target API level 30 or lower, implicitly by declaring an <intent-filter>. Content "
            "providers are additionally exported by default when targeting API level 16 or lower."
        ),
        remediation=(
            'Set android:exported="false" on components that are only used inside the app. '
            "If the component must be reachable by other apps, protect it with android:permission "
            "using a signature-level custom permission, and validate all incoming intent data."
        ),
        references=(
            "https://developer.android.com/privacy-and-security/risks/android-exported",
            "https://developer.android.com/guide/topics/manifest/activity-element#exported",
        ),
        cwe="CWE-926",
        masvs="MASVS-PLATFORM-1",
    )

    def check(self, ctx: ApkContext) -> Iterable[Finding]:
        manifest = ctx.manifest
        target_sdk = manifest.target_sdk or 1
        declared = manifest.declared_permissions
        for comp in manifest.components():
            exported, how = _is_exported(comp, target_sdk)
            if not exported:
                continue
            if comp.tag in ("activity", "activity-alias") and comp.is_launcher:
                continue  # the launcher entry point is exported by design
            permission = _effective_permission(comp)
            if permission:
                level = declared.get(permission)
                if level is None or level.lower() not in _WEAK_PROTECTION:
                    continue
                note = (
                    f" It is guarded by {permission}, but that custom permission has "
                    f'protectionLevel="{level}", so any app can request it.'
                )
            else:
                note = ""
            yield self.finding(
                f"{comp.tag} {comp.name} is exported ({how}) without a permission.{note}",
                Location(MANIFEST, comp.name),
                evidence=_evidence(comp),
                severity=_SEVERITY_BY_TAG.get(comp.tag, Severity.MEDIUM),
                component_type=comp.tag,
                component=comp.name,
            )


def _is_exported(comp: Component, target_sdk: int) -> tuple[bool, str]:
    explicit = comp.exported_attr
    if explicit is not None:
        return explicit, 'android:exported="true"'
    if comp.tag == "provider":
        return target_sdk <= 16, "default for targetSdkVersion <= 16"
    if comp.intent_filters:
        return True, "implicitly, via <intent-filter>"
    return False, ""


def _effective_permission(comp: Component) -> str | None:
    perm = comp.permission
    if perm:
        return perm
    if comp.tag == "provider":
        read = android_attr(comp.element, "readPermission")
        write = android_attr(comp.element, "writePermission")
        if read and write:
            return read
    return None


def _evidence(comp: Component) -> str:
    actions = comp.actions()
    if actions:
        shown = ", ".join(actions[:3]) + (" ..." if len(actions) > 3 else "")
        return f'<{comp.tag} android:name="{comp.name}"> actions: {shown}'
    return f'<{comp.tag} android:name="{comp.name}">'
