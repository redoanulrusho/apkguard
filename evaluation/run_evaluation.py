"""Scan every evaluation APK and summarise runtime and findings per rule.

Usage (after ``python evaluation/fetch_apks.py``)::

    python evaluation/run_evaluation.py [--apks DIR] [--out DIR]

Writes ``findings.csv`` (one row per finding) and ``summary.json`` / ``summary.md`` (per-app and
per-rule aggregates) to ``evaluation/results/``. All rules run with the default configuration.
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import time
from collections import Counter
from pathlib import Path
from typing import Any

from apkguard.config import Config
from apkguard.loader import ApkLoadError
from apkguard.model import Finding
from apkguard.scanner import scan_apk

HERE = Path(__file__).resolve().parent
#: One CSV row per finding, and one statistics record per scanned APK.
Row = dict[str, str]
AppStats = dict[str, Any]

CSV_FIELDS = ["package", "rule_id", "severity", "file", "symbol", "message"]


def finding_row(package: str, finding: Finding) -> Row:
    return {
        "package": package,
        "rule_id": finding.rule_id,
        "severity": finding.severity.label,
        "file": finding.location.file,
        "symbol": finding.location.symbol or "",
        "message": finding.message,
    }


def scan_all(entries: list[dict[str, str]], apk_dir: Path) -> tuple[list[AppStats], list[Row]]:
    apps: list[AppStats] = []
    rows: list[Row] = []
    for entry in entries:
        path = apk_dir / entry["file"]
        started = time.perf_counter()
        try:
            result = scan_apk(path, Config())
        except ApkLoadError as exc:
            apps.append({"file": entry["file"], "error": str(exc)})
            print(f"ERROR {entry['file']}: {exc}")
            continue
        seconds = time.perf_counter() - started
        app_rows = [finding_row(entry["package"], f) for f in result.findings]
        rows.extend(app_rows)
        apps.append(
            {
                "file": entry["file"],
                "package": entry["package"],
                "size_kb": round(path.stat().st_size / 1024),
                "seconds": round(seconds, 2),
                "findings": len(app_rows),
                "rule_errors": [f"{e.rule_id}: {e.error}" for e in result.errors],
            }
        )
        print(f"{seconds:6.2f}s {len(app_rows):5d} findings  {entry['file']}")
    return apps, rows


def summarise(apps: list[AppStats], rows: list[Row]) -> dict[str, Any]:
    scanned = [a for a in apps if "error" not in a]
    seconds = [a["seconds"] for a in scanned]
    per_rule: dict[str, dict[str, int]] = {}
    for row in rows:
        stats = per_rule.setdefault(row["rule_id"], {"total": 0, "apps": 0})
        stats["total"] += 1
    for rule_id, stats in per_rule.items():
        stats["apps"] = len({r["package"] for r in rows if r["rule_id"] == rule_id})
    return {
        "apks_scanned": len(scanned),
        "apks_failed": len(apps) - len(scanned),
        "total_size_mb": round(sum(a["size_kb"] for a in scanned) / 1024, 1),
        "runtime_seconds": {
            "total": round(sum(seconds), 1),
            "mean": round(statistics.mean(seconds), 2),
            "median": round(statistics.median(seconds), 2),
            "max": max(seconds),
        },
        "findings": {"total": len(rows)},
        "by_severity": dict(Counter(r["severity"] for r in rows)),
        "per_rule": dict(sorted(per_rule.items())),
        "apps": apps,
    }


def summary_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "| Rule | Findings | Apps affected |",
        "|---|---:|---:|",
    ]
    for rule_id, s in summary["per_rule"].items():
        lines.append(f"| {rule_id} | {s['total']} | {s['apps']} |")
    lines += ["", "| APK | Size (KB) | Time (s) | Findings |", "|---|---:|---:|---:|"]
    for a in summary["apps"]:
        if "error" in a:
            lines.append(f"| {a['file']} | - | - | error |")
        else:
            lines.append(f"| {a['file']} | {a['size_kb']} | {a['seconds']} | {a['findings']} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--apks", type=Path, default=HERE / "apks")
    parser.add_argument("--out", type=Path, default=HERE / "results")
    args = parser.parse_args()
    entries = json.loads((HERE / "apks.json").read_text(encoding="utf-8"))["apks"]

    apps, rows = scan_all(entries, args.apks)
    summary = summarise(apps, rows)

    args.out.mkdir(parents=True, exist_ok=True)
    with (args.out / "findings.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (args.out / "summary.md").write_text(summary_markdown(summary), encoding="utf-8")
    print(json.dumps({k: v for k, v in summary.items() if k not in ("apps", "per_rule")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
