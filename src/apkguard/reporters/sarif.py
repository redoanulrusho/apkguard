"""SARIF 2.1.0 report, compatible with GitHub code scanning."""

from __future__ import annotations

import json
import os
from pathlib import Path

from apkguard.model import Finding, RuleMeta, Severity
from apkguard.rules import RULES_BY_ID
from apkguard.scanner import ScanResult

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/apkguard/apkguard"

LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
# GitHub maps security-severity to critical (>= 9.0), high (7.0-8.9), medium (4.0-6.9), low.
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def _pascal(title: str) -> str:
    return "".join(word[:1].upper() + word[1:] for word in title.replace("/", " ").split())


def _rule_descriptor(meta: RuleMeta) -> dict[str, object]:
    tags = ["security", meta.category]
    if meta.cwe:
        tags.append(f"external/cwe/{meta.cwe.lower()}")
    help_md = f"{meta.description}\n\n**Remediation:** {meta.remediation}"
    if meta.references:
        help_md += "\n\n**References:**\n" + "\n".join(f"- {r}" for r in meta.references)
    descriptor: dict[str, object] = {
        "id": meta.id,
        "name": _pascal(meta.title),
        "shortDescription": {"text": meta.title},
        "fullDescription": {"text": meta.description},
        "help": {
            "text": f"{meta.description}\n\nRemediation: {meta.remediation}",
            "markdown": help_md,
        },
        "defaultConfiguration": {"level": LEVELS[meta.severity]},
        "properties": {
            "tags": tags,
            "precision": "medium",
            "security-severity": SECURITY_SEVERITY[meta.severity],
        },
    }
    if meta.references:
        descriptor["helpUri"] = meta.references[0]
    return descriptor


def _artifact_uri(apk_path: str) -> str:
    """Path of the APK relative to the working directory (GitHub resolves it from repo root)."""
    path = Path(apk_path)
    try:
        rel = os.path.relpath(path.resolve(), Path.cwd().resolve())
    except ValueError:  # different drive on Windows
        rel = path.name
    if rel.startswith(".."):
        rel = path.name
    return rel.replace(os.sep, "/")


def _result(finding: Finding, rule_index: dict[str, int], uri: str) -> dict[str, object]:
    loc = finding.location
    text = f"{finding.message} [{loc}]"
    logical: dict[str, object] = {"fullyQualifiedName": str(loc), "kind": "member"}
    if loc.symbol:
        logical["name"] = loc.symbol
    result: dict[str, object] = {
        "ruleId": finding.rule_id,
        "level": LEVELS[finding.severity],
        "message": {"text": text},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": 1},
                },
                "logicalLocations": [logical],
            }
        ],
        "partialFingerprints": {"apkguardFingerprint/v1": finding.fingerprint},
        "properties": {
            "severity": finding.severity.label,
            "security-severity": SECURITY_SEVERITY[finding.severity],
            "apkEntry": loc.file,
            "evidence": finding.evidence,
        },
    }
    if finding.rule_id in rule_index:
        result["ruleIndex"] = rule_index[finding.rule_id]
    if finding.suppressed:
        result["suppressions"] = [
            {"kind": "external", "justification": finding.suppression_reason or ""}
        ]
    return result


def to_sarif(result: ScanResult) -> dict[str, object]:
    metas = list(result.rules)
    known = {m.id for m in metas}
    for f in result.findings:  # findings from rules not in the active list (defensive)
        if f.rule_id not in known and f.rule_id in RULES_BY_ID:
            metas.append(RULES_BY_ID[f.rule_id].meta)
            known.add(f.rule_id)
    rule_index = {m.id: i for i, m in enumerate(metas)}
    uri = _artifact_uri(result.apk_path)
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "APKGuard",
                        "version": result.tool_version,
                        "semanticVersion": result.tool_version,
                        "informationUri": INFO_URI,
                        "rules": [_rule_descriptor(m) for m in metas],
                    }
                },
                "automationDetails": {"id": f"apkguard/{result.package}/"},
                "artifacts": [{"location": {"uri": uri, "uriBaseId": "%SRCROOT%"}}],
                "results": [_result(f, rule_index, uri) for f in result.findings],
                "invocations": [
                    {
                        "executionSuccessful": not result.errors,
                        "toolExecutionNotifications": [
                            {"level": "error", "message": {"text": f"{e.rule_id}: {e.error}"}}
                            for e in result.errors
                        ],
                    }
                ],
            }
        ],
    }


def render_sarif(result: ScanResult) -> str:
    return json.dumps(to_sarif(result), indent=2, ensure_ascii=False) + "\n"
