"""JSON report."""

from __future__ import annotations

import json

from apkguard.scanner import ScanResult


def to_dict(result: ScanResult) -> dict[str, object]:
    return {
        "tool": {"name": "apkguard", "version": result.tool_version},
        "apk": {
            "path": result.apk_path,
            "package": result.package,
            "version_name": result.version_name,
            "min_sdk": result.min_sdk,
            "target_sdk": result.target_sdk,
        },
        "summary": {
            "total": len(result.gating_findings),
            "suppressed": len(result.findings) - len(result.active_findings),
            "by_severity": result.counts(),
            "library_findings": {
                "mode": result.library_mode.value,
                "separated": len(result.separated_findings),
                "by_library": result.library_counts(),
            },
            "duration_seconds": round(result.duration_s, 3),
        },
        "findings": [f.to_dict() for f in result.findings],
        "rules": [
            {
                "id": m.id,
                "title": m.title,
                "severity": m.severity.label,
                "category": m.category,
                "cwe": m.cwe,
                "masvs": m.masvs,
            }
            for m in result.rules
        ],
        "errors": [{"rule_id": e.rule_id, "error": e.error} for e in result.errors],
    }


def render_json(result: ScanResult) -> str:
    return json.dumps(to_dict(result), indent=2, ensure_ascii=False) + "\n"
