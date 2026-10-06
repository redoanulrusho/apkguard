"""Androguard-independent representation of an APK that rules operate on.

Rules never touch androguard directly. The loader (:mod:`apkguard.loader`) converts an APK into
an :class:`ApkContext`; unit tests build the same structures synthetically, which keeps every rule
testable without real APK files.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field

from lxml import etree

ANDROID_NS = "http://schemas.android.com/apk/res/android"
COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")


def android_attr(element: etree._Element, name: str) -> str | None:
    """Return an ``android:`` namespaced attribute (falling back to an un-namespaced one)."""
    value = element.get(f"{{{ANDROID_NS}}}{name}")
    if value is None:
        value = element.get(name)
    return str(value) if value is not None else None


def parse_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered in ("true", "1", "0xffffffff", "-1"):
        return True
    if lowered in ("false", "0", "0x0"):
        return False
    return None  # resource reference or unknown value


def parse_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value, 0)
    except ValueError:
        return None


@dataclass
class Component:
    tag: str
    name: str
    element: etree._Element

    @property
    def exported_attr(self) -> bool | None:
        return parse_bool(android_attr(self.element, "exported"))

    @property
    def permission(self) -> str | None:
        return android_attr(self.element, "permission")

    @property
    def intent_filters(self) -> list[etree._Element]:
        return list(self.element.findall("intent-filter"))

    def actions(self) -> list[str]:
        out: list[str] = []
        for flt in self.intent_filters:
            for action in flt.findall("action"):
                value = android_attr(action, "name")
                if value:
                    out.append(value)
        return out

    def categories(self) -> list[str]:
        out: list[str] = []
        for flt in self.intent_filters:
            for cat in flt.findall("category"):
                value = android_attr(cat, "name")
                if value:
                    out.append(value)
        return out

    @property
    def is_launcher(self) -> bool:
        return (
            "android.intent.action.MAIN" in self.actions()
            and "android.intent.category.LAUNCHER" in self.categories()
        )


class Manifest:
    """Thin helper around the decoded AndroidManifest.xml element tree."""

    def __init__(self, root: etree._Element) -> None:
        self.root = root

    @classmethod
    def from_string(cls, xml: str | bytes) -> Manifest:
        data = xml.encode("utf-8") if isinstance(xml, str) else xml
        return cls(etree.fromstring(data))

    @property
    def package(self) -> str:
        return str(self.root.get("package", ""))

    @property
    def application(self) -> etree._Element | None:
        return self.root.find("application")

    def app_attr(self, name: str) -> str | None:
        app = self.application
        return android_attr(app, name) if app is not None else None

    @property
    def min_sdk(self) -> int | None:
        sdk = self.root.find("uses-sdk")
        value = parse_int(android_attr(sdk, "minSdkVersion")) if sdk is not None else None
        return value if value is not None else (1 if sdk is not None else None)

    @property
    def target_sdk(self) -> int | None:
        sdk = self.root.find("uses-sdk")
        if sdk is None:
            return None
        value = parse_int(android_attr(sdk, "targetSdkVersion"))
        # Android defaults targetSdkVersion to minSdkVersion when absent.
        return value if value is not None else self.min_sdk

    @property
    def permissions(self) -> list[str]:
        names: list[str] = []
        for tag in ("uses-permission", "uses-permission-sdk-23"):
            for el in self.root.findall(tag):
                value = android_attr(el, "name")
                if value and value not in names:
                    names.append(value)
        return names

    @property
    def declared_permissions(self) -> dict[str, str]:
        """Custom permissions declared by the app: name -> protectionLevel."""
        out: dict[str, str] = {}
        for el in self.root.findall("permission"):
            name = android_attr(el, "name")
            if name:
                out[name] = android_attr(el, "protectionLevel") or "normal"
        return out

    def components(self) -> Iterator[Component]:
        app = self.application
        if app is None:
            return
        for tag in COMPONENT_TAGS:
            for el in app.findall(tag):
                name = android_attr(el, "name") or "<unnamed>"
                if name.startswith("."):
                    name = self.package + name
                yield Component(tag=tag, name=name, element=el)


@dataclass
class Instruction:
    """A single Dalvik instruction, reduced to what the rules need.

    ``regs`` are register operands, ``literal`` an integer constant, ``string`` the value of a
    ``const-string`` and ``ref`` a referenced method/field/type (e.g.
    ``Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;``).
    """

    op: str
    regs: tuple[int, ...] = ()
    literal: int | None = None
    string: str | None = None
    ref: str | None = None


@dataclass
class MethodInfo:
    class_name: str
    name: str
    descriptor: str = "()V"
    instructions: list[Instruction] = field(default_factory=list)

    @property
    def full_name(self) -> str:
        return f"{self.class_name}->{self.name}{self.descriptor}"

    @property
    def short_name(self) -> str:
        return f"{self.class_name}->{self.name}"


@dataclass
class ClassInfo:
    name: str
    superclass: str | None = "Ljava/lang/Object;"
    interfaces: tuple[str, ...] = ()
    methods: list[MethodInfo] = field(default_factory=list)
    source_dex: str = "classes.dex"

    def method(self, name: str) -> MethodInfo | None:
        for m in self.methods:
            if m.name == name:
                return m
        return None


@dataclass
class StringItem:
    """A string found somewhere in the APK, with its origin for reporting."""

    value: str
    file: str
    symbol: str | None = None


@dataclass
class ApkContext:
    path: str
    manifest: Manifest
    classes: list[ClassInfo] = field(default_factory=list)
    strings: list[StringItem] = field(default_factory=list)
    network_security_config: etree._Element | None = None
    network_security_config_path: str | None = None
    exclude_packages: tuple[str, ...] = ()

    def app_classes(self) -> Iterator[ClassInfo]:
        """Classes not excluded via the ``exclude_packages`` configuration option."""
        for cls in self.classes:
            if self.exclude_packages and cls.name.startswith(self.exclude_packages):
                continue
            yield cls

    def app_methods(self) -> Iterator[MethodInfo]:
        for cls in self.app_classes():
            yield from cls.methods
