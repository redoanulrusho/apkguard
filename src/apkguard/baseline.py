"""Baselines: accept today's findings so that CI fails only on new ones.

A baseline is a JSON file listing the fingerprints of the findings that existed when it was
created (``apkguard scan app.apk --write-baseline apkguard-baseline.json``). A later scan with
``--baseline apkguard-baseline.json`` marks every finding as ``new`` or ``unchanged``; only new
findings are shown in the table and count towards ``--fail-on``.

Fingerprints (:attr:`apkguard.model.Finding.fingerprint`) combine rule ID, location and evidence,
so a finding stays "unchanged" when the message wording or severity changes, but becomes "new"
when it moves to another class or method.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from apkguard.model import Finding

FORMAT = "apkguard-baseline"
VERSION = 1

NEW = "new"
UNCHANGED = "unchanged"


class BaselineError(Exception):
    """Raised when a baseline file is missing or malformed."""


@dataclass(frozen=True)
class Baseline:
    fingerprints: frozenset[str]
    package: str | None = None
    source: str | None = None


@dataclass(frozen=True)
class BaselineComparison:
    """Outcome of comparing a scan with a baseline."""

    source: str | None
    new: int
    unchanged: int
    #: Baseline entries not found any more (fixed, or moved so their fingerprint changed).
    absent: int


def baseline_document(
    findings: Iterable[Finding], package: str, tool_version: str
) -> dict[str, Any]:
    """Build the JSON document for a baseline of ``findings``.

    Suppressed findings are left out: the configuration already accepts them. Besides the
    fingerprint, each entry stores the rule, severity and location so that the file can be
    reviewed in a pull request.
    """
    entries = {
        f.fingerprint: {
            "fingerprint": f.fingerprint,
            "rule_id": f.rule_id,
            "severity": f.severity.label,
            "location": str(f.location),
        }
        for f in findings
        if not f.suppressed
    }
    return {
        "format": FORMAT,
        "version": VERSION,
        "tool_version": tool_version,
        "package": package,
        # Sorted so that regenerating an unchanged baseline produces an identical file.
        "findings": [entries[key] for key in sorted(entries)],
    }


def write_baseline(
    path: str | Path, findings: Iterable[Finding], package: str, version: str
) -> int:
    """Write a baseline file and return the number of entries."""
    document = baseline_document(findings, package, version)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(document, indent=2, ensure_ascii=False) + "\n")
    return len(document["findings"])


def load_baseline(path: str | Path) -> Baseline:
    p = Path(path)
    if not p.is_file():
        raise BaselineError(f"baseline file not found: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise BaselineError(f"baseline {p} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or data.get("format") != FORMAT:
        raise BaselineError(f'{p} is not an APKGuard baseline (missing "format": "{FORMAT}")')
    if data.get("version") != VERSION:
        raise BaselineError(f"{p}: unsupported baseline version {data.get('version')!r}")
    entries = data.get("findings")
    if not isinstance(entries, list) or not all(
        isinstance(e, dict) and isinstance(e.get("fingerprint"), str) for e in entries
    ):
        raise BaselineError(f"{p}: 'findings' must be a list of objects with a 'fingerprint'")
    package = data.get("package")
    return Baseline(
        fingerprints=frozenset(e["fingerprint"] for e in entries),
        package=package if isinstance(package, str) else None,
        source=str(p),
    )


def apply_baseline(findings: Iterable[Finding], baseline: Baseline) -> BaselineComparison:
    """Mark each finding as new or unchanged and count baseline entries that disappeared."""
    seen: set[str] = set()
    new = unchanged = 0
    for finding in findings:
        if finding.fingerprint in baseline.fingerprints:
            finding.baseline_state = UNCHANGED
            seen.add(finding.fingerprint)
            unchanged += 1
        else:
            finding.baseline_state = NEW
            new += 1
    return BaselineComparison(
        source=baseline.source,
        new=new,
        unchanged=unchanged,
        absent=len(baseline.fingerprints - seen),
    )
