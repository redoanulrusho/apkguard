"""Convert an APK file into an :class:`~apkguard.context.ApkContext` using androguard."""

from __future__ import annotations

import logging
import zipfile
from pathlib import Path
from typing import Any

from lxml import etree

from apkguard.context import (
    ApkContext,
    ClassInfo,
    Instruction,
    Manifest,
    MethodInfo,
    StringItem,
)

TEXT_ASSET_SUFFIXES = (
    ".json", ".properties", ".xml", ".txt", ".js", ".html", ".htm", ".cfg", ".conf", ".ini",
    ".yaml", ".yml", ".env", ".config", ".plist",
)  # fmt: skip
MAX_ASSET_BYTES = 1_000_000

_REGISTER = 0
_LITERAL = 1
_KIND = 0x100
_BINARY_XML_MAGIC = b"\x03\x00\x08\x00"


class ApkLoadError(Exception):
    """Raised when a file cannot be parsed as an APK."""


def _silence_androguard() -> None:
    try:
        from loguru import logger

        logger.remove()
    except Exception:  # pragma: no cover - loguru is a transitive dependency of androguard
        logging.getLogger("androguard").setLevel(logging.ERROR)


def load_apk(path: str | Path, exclude_packages: tuple[str, ...] = ()) -> ApkContext:
    """Parse ``path`` and build the context rules operate on.

    ``exclude_packages`` are smali class-name prefixes (``Lcom/google/``); matching classes are
    skipped during conversion, which also speeds up scanning of large apps.
    """
    _silence_androguard()
    from androguard.core.apk import APK

    path = Path(path)
    if not path.is_file():
        raise ApkLoadError(f"file not found: {path}")
    if not zipfile.is_zipfile(path):
        raise ApkLoadError(f"not a valid APK (not a ZIP archive): {path}")
    try:
        apk = APK(str(path))
    except Exception as exc:  # androguard raises a variety of exception types
        raise ApkLoadError(f"failed to parse APK {path}: {exc}") from exc
    root = apk.get_android_manifest_xml()
    if root is None:
        raise ApkLoadError(f"APK has no readable AndroidManifest.xml: {path}")

    manifest = Manifest(root)
    ctx = ApkContext(path=str(path), manifest=manifest, exclude_packages=exclude_packages)
    ctx.classes = list(_load_classes(apk, exclude_packages))
    ctx.strings = list(_load_resource_strings(apk)) + list(_load_asset_strings(apk))
    nsc_path, nsc = _load_network_security_config(apk, manifest)
    ctx.network_security_config_path = nsc_path
    ctx.network_security_config = nsc
    return ctx


def _load_classes(apk: Any, exclude: tuple[str, ...]) -> list[ClassInfo]:
    from androguard.core.dex import DEX

    classes: list[ClassInfo] = []
    for dex_name in apk.get_dex_names():
        try:
            dex = DEX(apk.get_file(dex_name))
        except Exception:  # pragma: no cover - corrupted dex; skip rather than abort the scan
            continue
        for cls in dex.get_classes():
            name = cls.get_name()
            if exclude and name.startswith(exclude):
                continue
            info = ClassInfo(
                name=name,
                superclass=cls.get_superclassname(),
                interfaces=tuple(cls.get_interfaces() or ()),
                source_dex=dex_name,
            )
            for method in cls.get_methods():
                info.methods.append(
                    MethodInfo(
                        class_name=name,
                        name=method.get_name(),
                        descriptor=method.get_descriptor().replace(" ", ""),
                        instructions=_convert_code(method),
                    )
                )
            classes.append(info)
    return classes


def _convert_code(method: Any) -> list[Instruction]:
    code = method.get_code()
    if code is None:
        return []
    out: list[Instruction] = []
    for ins in code.get_bc().get_instructions():
        op = ins.get_name()
        regs: list[int] = []
        literal: int | None = None
        string: str | None = None
        ref: str | None = None
        for operand in ins.get_operands():
            kind = operand[0]
            kind_value = int(kind)
            if kind_value == _REGISTER:
                regs.append(int(operand[1]))
            elif kind_value == _LITERAL:
                literal = int(operand[1])
            elif kind_value & _KIND and len(operand) >= 3:
                if op.startswith("const-string"):
                    string = str(operand[2])
                else:
                    ref = str(operand[2]).replace(" ", "")
        out.append(Instruction(op=op, regs=tuple(regs), literal=literal, string=string, ref=ref))
    return out


def _load_resource_strings(apk: Any) -> list[StringItem]:
    items: list[StringItem] = []
    try:
        arsc = apk.get_android_resources()
    except Exception:  # pragma: no cover - APK without resources.arsc
        return items
    if arsc is None:
        return items
    for package in arsc.get_packages_names():
        try:
            xml = arsc.get_string_resources(package)
            root = etree.fromstring(xml)
        except Exception:  # pragma: no cover - malformed resource table
            continue
        for el in root.iter("string"):
            name = el.get("name")
            value = "".join(el.itertext())
            if name and value:
                items.append(StringItem(value, "res/values/strings.xml", f"string/{name}"))
    return items


def _load_asset_strings(apk: Any) -> list[StringItem]:
    items: list[StringItem] = []
    for name in apk.get_files():
        if not (name.startswith("assets/") or name.startswith("res/raw/")):
            continue
        if not name.lower().endswith(TEXT_ASSET_SUFFIXES):
            continue
        data = apk.get_file(name)
        if not data or len(data) > MAX_ASSET_BYTES or data[:4] == _BINARY_XML_MAGIC:
            continue  # skip empty, huge and binary-XML files
        text = data.decode("utf-8", errors="ignore")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if len(line.strip()) >= 10:
                items.append(StringItem(line.strip(), name, f"line {lineno}"))
    return items


def _load_network_security_config(
    apk: Any, manifest: Manifest
) -> tuple[str | None, etree._Element | None]:
    from androguard.core.axml import AXMLPrinter

    ref = manifest.app_attr("networkSecurityConfig")
    candidates: list[str] = []
    if ref and ref.startswith("@"):
        try:
            res_id = int(ref[1:], 16)
            for _config, value in apk.get_android_resources().get_resolved_res_configs(res_id):
                if isinstance(value, str) and value.endswith(".xml"):
                    candidates.append(value)
        except Exception:  # unresolvable reference; fall back to the conventional path
            pass
    if ref:
        candidates.append("res/xml/network_security_config.xml")
    for candidate in candidates:
        try:
            data = apk.get_file(candidate)
        except Exception:
            continue
        if not data:
            continue
        obj: etree._Element | None = None
        try:
            if data[:4] == _BINARY_XML_MAGIC:
                obj = AXMLPrinter(data).get_xml_obj()
            else:  # some build tools / tests ship plain-text XML
                obj = etree.fromstring(data)
        except Exception:
            continue
        if obj is not None:
            return candidate, obj
    return None, None


__all__ = ["ApkLoadError", "load_apk"]
