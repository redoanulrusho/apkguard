"""Scan every evaluation APK and summarise runtime and findings per rule.

Usage (after ``python evaluation/fetch_apks.py``)::

    python evaluation/run_evaluation.py [--apks DIR] [--out DIR]

Writes ``findings.csv`` (one row per finding) and ``summary.json`` / ``summary.md`` (per-app and
per-rule aggregates) to ``evaluation/results/``. All rules run with the default configuration,
except that library findings are *included*, so the data shows both the full noise and the
effect of separating third-party library code (the ``origin`` column).
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
from apkguard.libraries import LibraryMode
from apkguard.loader import ApkLoadError
from apkguard.model import Finding
from apkguard.scanner import scan_apk

HERE = Path(__file__).resolve().parent
#: One CSV row per finding, and one statistics record per scanned APK.
Row = dict[str, str]
AppStats = dict[str, Any]

CSV_FIELDS = ["package", "rule_id", "severity", "origin", "library", "file", "symbol", "message"]


def evaluation_config() -> Config:
    # Keep library findings in the output; the "origin" column records where they came from.
    return Config(library_mode=LibraryMode.INCLUDE)


def looks_obfuscated(symbol: str) -> bool:
    """Heuristic: an R8-renamed class such as ``La2;`` or ``Lq/f;`` (all names <= 3 chars)."""
    if not symbol.startswith("L") or ";" not in symbol:
        return False
    parts = symbol[1 : symbol.index(";")].split("/")
    return all(len(part) <= 3 for part in parts)


def finding_row(package: str, finding: Finding) -> Row:
    return {
        "package": package,
        "rule_id": finding.rule_id,
        "severity": finding.severity.label,
        "origin": "library" if finding.library else "app",
        "library": finding.library or "",
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
            result = scan_apk(path, evaluation_config())
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
                "library_findings": sum(r["origin"] == "library" for r in app_rows),
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
        stats = per_rule.setdefault(row["rule_id"], {"total": 0, "app": 0, "library": 0, "apps": 0})
        stats["total"] += 1
        stats[row["origin"]] += 1
    for rule_id, stats in per_rule.items():
        stats["apps"] = len({r["package"] for r in rows if r["rule_id"] == rule_id})
    app_rows = [r for r in rows if r["origin"] == "app"]
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
        "findings": {
            "total": len(rows),
            "app": len(app_rows),
            "library": len(rows) - len(app_rows),
            # App-attributed findings in R8-renamed classes: often library code that
            # package-based detection cannot recognise.
            "app_in_obfuscated_classes": sum(looks_obfuscated(r["symbol"]) for r in app_rows),
        },
        "by_severity_all": dict(Counter(r["severity"] for r in rows)),
        "by_severity_app": dict(Counter(r["severity"] for r in app_rows)),
        "top_libraries": Counter(r["library"] for r in rows if r["library"]).most_common(10),
        "per_rule": dict(sorted(per_rule.items())),
        "apps": apps,
    }


def summary_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "| Rule | Findings (all) | In app code | In libraries | Apps affected |",
        "|---|---:|---:|---:|---:|",
    ]
    for rule_id, s in summary["per_rule"].items():
        lines.append(f"| {rule_id} | {s['total']} | {s['app']} | {s['library']} | {s['apps']} |")
    lines += [
        "",
        "| APK | Size (KB) | Time (s) | Findings | In libraries |",
        "|---|---:|---:|---:|---:|",
    ]
    for a in summary["apps"]:
        if "error" in a:
            lines.append(f"| {a['file']} | - | - | error | - |")
        else:
            lines.append(
                f"| {a['file']} | {a['size_kb']} | {a['seconds']} | {a['findings']} "
                f"| {a['library_findings']} |"
            )
    return "\n".join(lines) + "\n"


def write_text(path: Path, text: str) -> None:
    # Explicit "\n" line endings so the committed results are identical on Windows and Linux.
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


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
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    write_text(args.out / "summary.json", json.dumps(summary, indent=2) + "\n")
    write_text(args.out / "summary.md", summary_markdown(summary))
    print(json.dumps({k: v for k, v in summary.items() if k not in ("apps", "per_rule")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
