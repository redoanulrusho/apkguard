"""Core data types shared by rules, the scanner and reporters."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Finding severity. Ordered so that comparisons (``>=``) work for thresholds."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            choices = ", ".join(s.label for s in cls)
            raise ValueError(f"unknown severity {value!r} (expected one of: {choices})") from exc

    @property
    def label(self) -> str:
        return self.name.lower()


class Category:
    MANIFEST = "manifest"
    PERMISSIONS = "permissions"
    CODE = "code"
    SECRETS = "secrets"


@dataclass(frozen=True)
class RuleMeta:
    """Static metadata describing a rule."""

    id: str
    title: str
    severity: Severity
    category: str
    description: str
    remediation: str
    references: tuple[str, ...] = ()
    cwe: str | None = None
    masvs: str | None = None


@dataclass(frozen=True)
class Location:
    """Where a finding was observed inside the APK.

    ``file`` is a path inside the APK (e.g. ``AndroidManifest.xml`` or ``classes.dex``) and
    ``symbol`` a logical location (component name, ``Lcom/Foo;->bar``, resource name, ...).
    """

    file: str
    symbol: str | None = None

    def __str__(self) -> str:
        return f"{self.file}:{self.symbol}" if self.symbol else self.file


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    category: str
    message: str
    location: Location
    remediation: str
    evidence: str | None = None
    suppressed: bool = False
    suppression_reason: str | None = None
    #: Package of the third-party library the finding is in (e.g. ``androidx``), None for app code.
    library: str | None = None
    extra: dict[str, object] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        """Stable identifier used to de-duplicate findings across runs (SARIF, baselines)."""
        loc = self.location
        raw = f"{self.rule_id}|{loc.file}|{loc.symbol or ''}|{self.evidence or ''}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.label,
            "category": self.category,
            "message": self.message,
            "location": {"file": self.location.file, "symbol": self.location.symbol},
            "remediation": self.remediation,
            "evidence": self.evidence,
            "fingerprint": self.fingerprint,
            "origin": "library" if self.library else "app",
            "library": self.library,
            "suppressed": self.suppressed,
        }
        if self.suppression_reason:
            data["suppression_reason"] = self.suppression_reason
        if "occurrences" in self.extra:
            data["occurrences"] = self.extra["occurrences"]
        return data
