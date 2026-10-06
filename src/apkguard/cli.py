"""Command-line interface: ``apkguard scan app.apk``."""

from __future__ import annotations

import argparse
import contextlib
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from rich.console import Console
from rich.table import Table

from apkguard import __version__
from apkguard.config import Config, ConfigError, find_config, load_config, to_smali_prefix
from apkguard.loader import ApkLoadError
from apkguard.model import Severity
from apkguard.rules import ALL_RULES, RULES_BY_ID

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_SCAN_ERROR = 3

DEFAULT_FAIL_ON = Severity.HIGH
SEVERITY_CHOICES = [s.label for s in Severity] + ["none"]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apkguard",
        description="Static security scanner for Android APKs, built for CI/CD pipelines.",
    )
    parser.add_argument("--version", action="version", version=f"apkguard {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    scan = sub.add_parser("scan", help="scan an APK file", description="Scan an APK file.")
    scan.add_argument("apk", help="path to the .apk file")
    scan.add_argument(
        "-f",
        "--format",
        choices=["table", "json", "sarif", "html"],
        default="table",
        help="primary output format (default: table)",
    )
    scan.add_argument(
        "-o", "--output", metavar="FILE", help="write the primary output to FILE instead of stdout"
    )
    scan.add_argument("--json", metavar="FILE", dest="json_out", help="also write a JSON report")
    scan.add_argument(
        "--sarif", metavar="FILE", dest="sarif_out", help="also write a SARIF 2.1.0 report"
    )
    scan.add_argument(
        "--html", metavar="FILE", dest="html_out", help="also write a standalone HTML report"
    )
    scan.add_argument(
        "--fail-on",
        choices=SEVERITY_CHOICES,
        default=None,
        help="exit with code 1 if any unsuppressed finding has at least this severity "
        f"(default: config value or '{DEFAULT_FAIL_ON.label}'; 'none' never fails)",
    )
    scan.add_argument(
        "-c",
        "--config",
        metavar="FILE",
        help="configuration file (default: ./.apkguard.yml if present)",
    )
    scan.add_argument("--no-config", action="store_true", help="ignore any configuration file")
    scan.add_argument(
        "--disable",
        metavar="RULE_ID",
        action="append",
        default=[],
        help="disable a rule (repeatable)",
    )
    scan.add_argument(
        "--exclude-package",
        metavar="PKG",
        action="append",
        default=[],
        help="skip code in this package for code/secret rules, e.g. com.google (repeatable)",
    )
    scan.add_argument(
        "--min-severity",
        choices=[s.label for s in Severity],
        default="info",
        help="hide table rows below this severity (does not affect exit code)",
    )
    scan.add_argument(
        "--show-suppressed", action="store_true", help="include suppressed findings in the table"
    )
    scan.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="do not print the table (reports and exit code only)",
    )

    sub.add_parser("rules", help="list available rules")
    return parser


def _console(stream: TextIO | None = None, *, color: bool = True) -> Console:
    target = stream or sys.stdout
    # Non-interactive output (CI logs, files) defaults to 80 columns in rich; widen it so the
    # table stays readable.
    width = None if target.isatty() else 160
    return Console(file=target, no_color=not color, highlight=False, width=width)


def _list_rules(console: Console) -> int:
    table = Table(header_style="bold")
    table.add_column("ID", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Category", no_wrap=True)
    table.add_column("Title")
    table.add_column("CWE", no_wrap=True)
    for rule in ALL_RULES:
        m = rule.meta
        table.add_row(m.id, m.severity.label, m.category, m.title, m.cwe or "")
    console.print(table)
    return EXIT_OK


def _resolve_config(args: argparse.Namespace) -> Config:
    known = set(RULES_BY_ID)
    if args.no_config:
        config = Config()
    else:
        path = Path(args.config) if args.config else find_config()
        config = load_config(path, known)
    for rule_id in args.disable:
        if rule_id not in known:
            raise ConfigError(f"--disable: unknown rule id {rule_id!r}")
        config.disable.add(rule_id)
    if args.exclude_package:
        config.exclude_packages += tuple(to_smali_prefix(p) for p in args.exclude_package)
    return config


def _write(path: str, content: str) -> None:
    target = Path(path)
    if target.parent and not target.parent.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def _scan(args: argparse.Namespace) -> int:
    from apkguard.reporters import FILE_RENDERERS
    from apkguard.reporters.terminal import print_table
    from apkguard.scanner import scan_apk

    err = _console(sys.stderr)
    try:
        config = _resolve_config(args)
    except ConfigError as exc:
        err.print(f"[red]Configuration error:[/red] {exc}")
        return EXIT_USAGE

    if args.fail_on is not None:
        threshold = None if args.fail_on == "none" else Severity.parse(args.fail_on)
    elif config.fail_on_set:
        threshold = config.fail_on
    else:
        threshold = DEFAULT_FAIL_ON

    try:
        result = scan_apk(args.apk, config)
    except ApkLoadError as exc:
        err.print(f"[red]Error:[/red] {exc}")
        return EXIT_SCAN_ERROR

    min_sev = Severity.parse(args.min_severity)
    if args.format == "table":
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                print_table(
                    result,
                    _console(fh, color=False),
                    show_suppressed=args.show_suppressed,
                    min_severity=min_sev,
                )
        elif not args.quiet:
            print_table(
                result, _console(), show_suppressed=args.show_suppressed, min_severity=min_sev
            )
    else:
        content = FILE_RENDERERS[args.format](result)
        if args.output:
            _write(args.output, content)
        else:
            sys.stdout.write(content)

    for fmt, path in (("json", args.json_out), ("sarif", args.sarif_out), ("html", args.html_out)):
        if path:
            _write(path, FILE_RENDERERS[fmt](result))
            err.print(f"[dim]Wrote {fmt.upper()} report to {path}[/dim]")

    if result.exceeds(threshold):
        assert threshold is not None
        failing = sum(1 for f in result.active_findings if f.severity >= threshold)
        err.print(
            f"[red]FAIL:[/red] {failing} finding(s) at or above severity '{threshold.label}'."
        )
        return EXIT_FINDINGS
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(ValueError, OSError):
                reconfigure(encoding="utf-8")
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _scan(args)
    if args.command == "rules":
        return _list_rules(_console())
    parser.print_help()
    return EXIT_USAGE


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
