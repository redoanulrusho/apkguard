"""Simulate an app upgrade in CI: baseline from the previous release, scan the current one.

Usage (after ``python evaluation/fetch_apks.py``)::

    python evaluation/run_baseline_eval.py [--apks DIR] [--out DIR]

For every app with a pinned previous version, this creates a baseline from the previous APK
(exactly what ``--write-baseline`` stores) and compares the current APK against it, the way
``--baseline`` does in CI. A finding counts as "new" when its fingerprint is not in the
baseline. Ideally only real changes show up as new; anything else is churn that a developer
would have to re-triage. Writes ``baseline_pairs.json`` and ``baseline_pairs.md``.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from apkguard.baseline import NEW, Baseline
from apkguard.config import Config
from apkguard.model import Severity
from apkguard.scanner import scan_apk

from run_evaluation import HERE, looks_obfuscated, write_text


def compare_versions(previous: Path, current: Path) -> dict[str, Any]:
    old = scan_apk(previous, Config())
    baseline = Baseline(frozenset(f.fingerprint for f in old.active_findings))
    new = scan_apk(current, Config())
    comparison = new.compare_with_baseline(baseline)
    new_findings = [f for f in new.active_findings if f.baseline_state == NEW]
    gating_high = [f for f in new.gating_findings if f.severity >= Severity.HIGH]
    return {
        "previous_findings": len(old.active_findings),
        "current_findings": len(new.active_findings),
        "new": comparison.new,
        "unchanged": comparison.unchanged,
        "absent": comparison.absent,
        "new_gating": len(new.gating_findings),
        # What a default CI gate (--fail-on high, library findings separate) would fail on.
        "new_gating_high": len(gating_high),
        "new_by_rule": dict(Counter(f.rule_id for f in new_findings)),
        "new_in_obfuscated_classes": sum(
            looks_obfuscated(f.location.symbol or "") for f in new_findings
        ),
        "new_findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.label,
                "location": str(f.location),
                "library": f.library,
                "obfuscated": looks_obfuscated(f.location.symbol or ""),
            }
            for f in new_findings
        ],
    }


def summary_markdown(pairs: list[dict[str, Any]]) -> str:
    lines = [
        "| App | Versions | Findings before / after | New | Unchanged | Gone "
        "| New in obfuscated classes |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for p in pairs:
        lines.append(
            f"| {p['package']} | {p['previous_version']} → {p['current_version']} "
            f"| {p['previous_findings']} / {p['current_findings']} | {p['new']} "
            f"| {p['unchanged']} | {p['absent']} | {p['new_in_obfuscated_classes']} |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--apks", type=Path, default=HERE / "apks")
    parser.add_argument("--out", type=Path, default=HERE / "results")
    args = parser.parse_args()
    pinned = json.loads((HERE / "apks.json").read_text(encoding="utf-8"))
    current_by_package = {e["package"]: e for e in pinned["apks"]}

    pairs: list[dict[str, Any]] = []
    for previous in pinned["previous_versions"]:
        current = current_by_package[previous["package"]]
        stats = compare_versions(args.apks / previous["file"], args.apks / current["file"])
        pairs.append(
            {
                "package": previous["package"],
                "previous_version": previous["version_name"],
                "current_version": current["version_name"],
                **stats,
            }
        )
        print(f"{previous['package']:45} new={stats['new']:4} unchanged={stats['unchanged']:4}")

    totals = {
        key: sum(p[key] for p in pairs)
        for key in (
            "current_findings",
            "new",
            "unchanged",
            "absent",
            "new_in_obfuscated_classes",
            "new_gating",
            "new_gating_high",
        )
    }
    rules: Counter[str] = Counter()
    for p in pairs:
        rules.update(p["new_by_rule"])
    summary = {
        "pairs": len(pairs),
        "totals": totals,
        "apps_with_no_new_findings": sum(p["new"] == 0 for p in pairs),
        "new_by_rule": dict(rules.most_common()),
        "apps": pairs,
    }
    args.out.mkdir(parents=True, exist_ok=True)
    write_text(args.out / "baseline_pairs.json", json.dumps(summary, indent=2) + "\n")
    write_text(args.out / "baseline_pairs.md", summary_markdown(pairs))
    print(json.dumps({k: v for k, v in summary.items() if k != "apps"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
