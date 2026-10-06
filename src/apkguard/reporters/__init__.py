"""Output formats for scan results."""

from __future__ import annotations

from collections.abc import Callable

from apkguard.reporters.html import render_html
from apkguard.reporters.json_report import render_json
from apkguard.reporters.sarif import render_sarif
from apkguard.scanner import ScanResult

FILE_RENDERERS: dict[str, Callable[[ScanResult], str]] = {
    "json": render_json,
    "sarif": render_sarif,
    "html": render_html,
}

__all__ = ["FILE_RENDERERS", "render_html", "render_json", "render_sarif"]
