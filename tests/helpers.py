"""Builders for synthetic APK contexts used by rule unit tests."""

from __future__ import annotations

from collections.abc import Iterable

from lxml import etree

from apkguard.context import ApkContext, ClassInfo, Instruction, Manifest, MethodInfo, StringItem
from apkguard.model import Finding
from apkguard.rules.base import Rule

NS = 'xmlns:android="http://schemas.android.com/apk/res/android"'


def manifest(
    *,
    app: str = "",
    body: str = "",
    min_sdk: int | None = 26,
    target_sdk: int | None = 35,
    permissions: Iterable[str] = (),
    package: str = "com.example.app",
    top: str = "",
) -> Manifest:
    """Build a Manifest. ``app`` is extra attributes for <application>, ``body`` its children."""
    sdk = ""
    if min_sdk is not None or target_sdk is not None:
        attrs = ""
        if min_sdk is not None:
            attrs += f' android:minSdkVersion="{min_sdk}"'
        if target_sdk is not None:
            attrs += f' android:targetSdkVersion="{target_sdk}"'
        sdk = f"<uses-sdk{attrs}/>"
    perms = "".join(
        f'<uses-permission android:name="{p if "." in p else "android.permission." + p}"/>'
        for p in permissions
    )
    xml = (
        f'<manifest {NS} package="{package}">{sdk}{perms}{top}'
        f"<application {app}>{body}</application></manifest>"
    )
    return Manifest.from_string(xml)


def ctx(
    m: Manifest | None = None,
    *,
    classes: Iterable[ClassInfo] = (),
    strings: Iterable[StringItem] = (),
    nsc: str | None = None,
    exclude_packages: tuple[str, ...] = (),
) -> ApkContext:
    return ApkContext(
        path="test.apk",
        manifest=m or manifest(app='android:allowBackup="false"'),
        classes=list(classes),
        strings=list(strings),
        network_security_config=etree.fromstring(nsc.encode()) if nsc else None,
        network_security_config_path="res/xml/network_security_config.xml" if nsc else None,
        exclude_packages=exclude_packages,
    )


# --- Dalvik instruction builders -------------------------------------------------------------


def const(reg: int, value: int) -> Instruction:
    return Instruction("const/4", (reg,), literal=value)


def const_string(reg: int, value: str) -> Instruction:
    return Instruction("const-string", (reg,), string=value)


def invoke(target: str, *regs: int, kind: str = "virtual") -> Instruction:
    return Instruction(f"invoke-{kind}", tuple(regs), ref=target)


def move_result(reg: int) -> Instruction:
    return Instruction("move-result-object", (reg,))


def new_instance(reg: int, type_name: str) -> Instruction:
    return Instruction("new-instance", (reg,), ref=type_name)


def new_array(reg: int, size_reg: int) -> Instruction:
    return Instruction("new-array", (reg, size_reg), ref="[B")


def fill_array(reg: int) -> Instruction:
    return Instruction("fill-array-data", (reg,))


def sget(reg: int, field: str) -> Instruction:
    return Instruction("sget-object", (reg,), ref=field)


def ret_void() -> Instruction:
    return Instruction("return-void")


def ret(reg: int) -> Instruction:
    return Instruction("return", (reg,))


def method(cls: str, name: str, *instructions: Instruction, descriptor: str = "()V") -> MethodInfo:
    return MethodInfo(cls, name, descriptor, list(instructions))


def klass(
    name: str,
    *methods: MethodInfo,
    superclass: str = "Ljava/lang/Object;",
    interfaces: Iterable[str] = (),
) -> ClassInfo:
    return ClassInfo(name, superclass, tuple(interfaces), list(methods))


def single_method_class(
    name: str, *instructions: Instruction, method_name: str = "run"
) -> ClassInfo:
    return klass(name, method(name, method_name, *instructions))


def run(rule: Rule, context: ApkContext) -> list[Finding]:
    return list(rule.check(context))
