"""Helpers shared by code-level rules."""

from __future__ import annotations

from collections.abc import Iterator

from apkguard.context import ApkContext, ClassInfo, MethodInfo
from apkguard.model import Location


def iter_methods(ctx: ApkContext) -> Iterator[tuple[ClassInfo, MethodInfo]]:
    """Yield (class, method) pairs for all non-excluded classes."""
    for cls in ctx.app_classes():
        for method in cls.methods:
            yield cls, method


def method_location(cls: ClassInfo, method: MethodInfo) -> Location:
    return Location(cls.source_dex, method.short_name)


def class_location(cls: ClassInfo) -> Location:
    return Location(cls.source_dex, cls.name)


def java_name(smali: str) -> str:
    """``Lcom/example/Foo;`` -> ``com.example.Foo``."""
    if smali.startswith("L") and smali.endswith(";"):
        return smali[1:-1].replace("/", ".")
    return smali


def implements(cls: ClassInfo, *types: str) -> bool:
    return any(t in cls.interfaces or t == cls.superclass for t in types)
