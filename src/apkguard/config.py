"""Configuration file (``.apkguard.yml``) loading and validation.

Example::

    fail_on: high
    disable:
      - AG-PERM-001
    severity_overrides:
      AG-MAN-005: low
    exclude_packages:
      - com.google.android.gms
    rule_options:
      AG-CODE-002:
        threshold: 12
    suppress:
      - rule: AG-MAN-004
        location: "com.example.DeepLinkActivity"
        reason: Deep link entry point, validated in onCreate
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from apkguard.model import Finding, Severity

DEFAULT_CONFIG_NAMES = (".apkguard.yml", ".apkguard.yaml", "apkguard.yml")
_KNOWN_KEYS = {"fail_on", "disable", "severity_overrides", "exclude_packages", "rule_options",
               "suppress"}  # fmt: skip


class ConfigError(Exception):
    """Raised for invalid configuration files."""


@dataclass
class Suppression:
    rule: str
    location: str | None = None  # fnmatch pattern against location file, symbol or "file:symbol"
    reason: str | None = None

    def matches(self, finding: Finding) -> bool:
        if self.rule not in ("*", finding.rule_id):
            return False
        if self.location is None:
            return True
        loc = finding.location
        targets = [loc.file, str(loc)]
        if loc.symbol:
            targets.append(loc.symbol)
        return any(fnmatch.fnmatchcase(t, self.location) for t in targets)


@dataclass
class Config:
    fail_on: Severity | None = None
    disable: set[str] = field(default_factory=set)
    severity_overrides: dict[str, Severity] = field(default_factory=dict)
    exclude_packages: tuple[str, ...] = ()
    rule_options: dict[str, dict[str, Any]] = field(default_factory=dict)
    suppress: list[Suppression] = field(default_factory=list)
    source: str | None = None

    def suppression_for(self, finding: Finding) -> Suppression | None:
        for sup in self.suppress:
            if sup.matches(finding):
                return sup
        return None


def to_smali_prefix(package: str) -> str:
    """``com.google`` or ``Lcom/google/`` -> ``Lcom/google/``."""
    pkg = package.strip()
    if pkg.startswith("L") and "/" in pkg:
        return pkg if pkg.endswith(("/", ";")) else pkg + "/"
    pkg = pkg.rstrip(".*").replace(".", "/")
    return f"L{pkg}/"


def find_config(start: Path | None = None) -> Path | None:
    base = start or Path.cwd()
    for name in DEFAULT_CONFIG_NAMES:
        candidate = base / name
        if candidate.is_file():
            return candidate
    return None


def load_config(path: str | Path | None, known_rules: set[str] | None = None) -> Config:
    """Load a config file. ``None`` returns the default (empty) configuration."""
    if path is None:
        return Config()
    p = Path(path)
    if not p.is_file():
        raise ConfigError(f"config file not found: {p}")
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {p}: {exc}") from exc
    config = parse_config(raw, known_rules)
    config.source = str(p)
    return config


def parse_config(raw: Any, known_rules: set[str] | None = None) -> Config:
    if not isinstance(raw, dict):
        raise ConfigError("config root must be a mapping")
    unknown = set(raw) - _KNOWN_KEYS
    if unknown:
        raise ConfigError(f"unknown config key(s): {', '.join(sorted(unknown))}")

    def check_rule(rule_id: str, where: str) -> str:
        if not isinstance(rule_id, str):
            raise ConfigError(f"{where}: rule id must be a string, got {rule_id!r}")
        if known_rules is not None and rule_id != "*" and rule_id not in known_rules:
            raise ConfigError(f"{where}: unknown rule id {rule_id!r}")
        return rule_id

    def severity(value: Any, where: str) -> Severity:
        try:
            return Severity.parse(str(value))
        except ValueError as exc:
            raise ConfigError(f"{where}: {exc}") from exc

    config = Config()
    if raw.get("fail_on") is not None:
        value = str(raw["fail_on"])
        config.fail_on = None if value.lower() == "none" else severity(value, "fail_on")

    disable = raw.get("disable") or []
    if not isinstance(disable, list):
        raise ConfigError("disable must be a list of rule ids")
    config.disable = {check_rule(r, "disable") for r in disable}

    overrides = raw.get("severity_overrides") or {}
    if not isinstance(overrides, dict):
        raise ConfigError("severity_overrides must be a mapping of rule id -> severity")
    config.severity_overrides = {
        check_rule(k, "severity_overrides"): severity(v, f"severity_overrides.{k}")
        for k, v in overrides.items()
    }

    excludes = raw.get("exclude_packages") or []
    if not isinstance(excludes, list) or not all(isinstance(e, str) for e in excludes):
        raise ConfigError("exclude_packages must be a list of package names")
    config.exclude_packages = tuple(to_smali_prefix(e) for e in excludes)

    options = raw.get("rule_options") or {}
    if not isinstance(options, dict) or not all(isinstance(v, dict) for v in options.values()):
        raise ConfigError("rule_options must map rule ids to mappings of option -> value")
    config.rule_options = {check_rule(k, "rule_options"): dict(v) for k, v in options.items()}

    suppress = raw.get("suppress") or []
    if not isinstance(suppress, list):
        raise ConfigError("suppress must be a list")
    for i, entry in enumerate(suppress):
        where = f"suppress[{i}]"
        if not isinstance(entry, dict) or "rule" not in entry:
            raise ConfigError(f"{where}: each suppression needs at least a 'rule' key")
        extra = set(entry) - {"rule", "location", "reason"}
        if extra:
            raise ConfigError(f"{where}: unknown key(s) {', '.join(sorted(extra))}")
        config.suppress.append(
            Suppression(
                rule=check_rule(entry["rule"], where),
                location=str(entry["location"]) if entry.get("location") is not None else None,
                reason=str(entry["reason"]) if entry.get("reason") is not None else None,
            )
        )
    return config
