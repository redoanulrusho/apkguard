"""Base class for rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import ClassVar

from apkguard.context import ApkContext
from apkguard.model import Finding, Location, RuleMeta, Severity


class Rule(ABC):
    """A single security check.

    Subclasses set :attr:`meta` and implement :meth:`check`, yielding findings created with
    :meth:`finding` so that metadata (ID, title, remediation) stays consistent.
    """

    meta: RuleMeta
    #: Tunable parameters and their defaults; overridable via ``rule_options`` in the config.
    default_options: ClassVar[dict[str, object]] = {}

    def __init__(self, options: dict[str, object] | None = None) -> None:
        self.options: dict[str, object] = {**self.default_options, **(options or {})}

    def option_int(self, name: str) -> int:
        value = self.options[name]
        if isinstance(value, bool) or not isinstance(value, int | str):
            raise ValueError(f"{self.meta.id}: option {name!r} must be an integer")
        return int(value)

    @abstractmethod
    def check(self, ctx: ApkContext) -> Iterable[Finding]:
        """Inspect ``ctx`` and yield findings."""

    def finding(
        self,
        message: str,
        location: Location,
        *,
        evidence: str | None = None,
        severity: Severity | None = None,
        **extra: object,
    ) -> Finding:
        return Finding(
            rule_id=self.meta.id,
            title=self.meta.title,
            severity=severity if severity is not None else self.meta.severity,
            category=self.meta.category,
            message=message,
            location=location,
            remediation=self.meta.remediation,
            evidence=evidence,
            extra=dict(extra),
        )
