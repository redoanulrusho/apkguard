"""Run rules against an APK context and apply configuration."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from apkguard import __version__
from apkguard.config import Config
from apkguard.context import ApkContext
from apkguard.libraries import LibraryMode, tag_library_findings
from apkguard.loader import load_apk
from apkguard.model import Finding, RuleMeta, Severity
from apkguard.rules import ALL_RULES, Rule


@dataclass
class RuleError:
    rule_id: str
    error: str


@dataclass
class ScanResult:
    apk_path: str
    package: str
    version_name: str | None
    min_sdk: int | None
    target_sdk: int | None
    findings: list[Finding]
    rules: list[RuleMeta]
    duration_s: float
    errors: list[RuleError] = field(default_factory=list)
    library_mode: LibraryMode = LibraryMode.SEPARATE
    tool_version: str = __version__

    @property
    def active_findings(self) -> list[Finding]:
        """Findings not suppressed by configuration (app and library code)."""
        return [f for f in self.findings if not f.suppressed]

    def is_separated(self, finding: Finding) -> bool:
        """True if ``finding`` is in library code and library findings are kept separate."""
        return self.library_mode is LibraryMode.SEPARATE and finding.library is not None

    @property
    def gating_findings(self) -> list[Finding]:
        """Findings that count for the summary and the ``--fail-on`` threshold."""
        return [f for f in self.active_findings if not self.is_separated(f)]

    @property
    def separated_findings(self) -> list[Finding]:
        """Active library findings reported separately (``library_findings: separate``)."""
        return [f for f in self.active_findings if self.is_separated(f)]

    def counts(self) -> dict[str, int]:
        out = {s.label: 0 for s in sorted(Severity, reverse=True)}
        for f in self.gating_findings:
            out[f.severity.label] += 1
        return out

    def library_counts(self) -> dict[str, int]:
        """Separated library findings per library package, most frequent first."""
        counts: dict[str, int] = {}
        for f in self.separated_findings:
            assert f.library is not None
            counts[f.library] = counts.get(f.library, 0) + 1
        return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))

    def exceeds(self, threshold: Severity | None) -> bool:
        if threshold is None:
            return False
        return any(f.severity >= threshold for f in self.gating_findings)


def build_rules(config: Config) -> list[Rule]:
    rules: list[Rule] = []
    for rule_cls in ALL_RULES:
        rule_id = rule_cls.meta.id
        if rule_id in config.disable:
            continue
        rules.append(rule_cls(config.rule_options.get(rule_id)))
    return rules


def run_rules(
    ctx: ApkContext, config: Config
) -> tuple[list[Finding], list[RuleMeta], list[RuleError]]:
    rules = build_rules(config)
    findings: list[Finding] = []
    errors: list[RuleError] = []
    for rule in rules:
        try:
            produced = list(rule.check(ctx))
        except Exception as exc:  # a broken rule must not abort the whole scan
            errors.append(RuleError(rule.meta.id, f"{type(exc).__name__}: {exc}"))
            continue
        for finding in produced:
            override = config.severity_overrides.get(finding.rule_id)
            if override is not None:
                finding.severity = override
            sup = config.suppression_for(finding)
            if sup is not None:
                finding.suppressed = True
                finding.suppression_reason = sup.reason or "suppressed by configuration"
            findings.append(finding)
    findings = _deduplicate(findings)
    tag_library_findings(findings, config.library_packages, ctx.manifest.package)
    if config.library_mode is LibraryMode.EXCLUDE:
        findings = [f for f in findings if f.library is None]
    findings.sort(key=lambda f: (-f.severity, f.rule_id, str(f.location)))
    return findings, [r.meta for r in rules], errors


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    """Merge findings with the same fingerprint (e.g. two identical calls in one method).

    Fingerprints identify findings in SARIF and baselines, so they must be unique per scan.
    The merged finding records how many times it was seen in ``extra["occurrences"]``.
    """
    unique: dict[str, Finding] = {}
    for finding in findings:
        first = unique.setdefault(finding.fingerprint, finding)
        if first is not finding:
            count = first.extra.get("occurrences", 1)
            first.extra["occurrences"] = (count if isinstance(count, int) else 1) + 1
    return list(unique.values())


def scan_context(ctx: ApkContext, config: Config | None = None) -> ScanResult:
    config = config or Config()
    start = time.perf_counter()
    findings, metas, errors = run_rules(ctx, config)
    return ScanResult(
        apk_path=ctx.path,
        package=ctx.manifest.package,
        version_name=ctx.manifest.root.get(
            "{http://schemas.android.com/apk/res/android}versionName"
        ),
        min_sdk=ctx.manifest.min_sdk,
        target_sdk=ctx.manifest.target_sdk,
        findings=findings,
        rules=metas,
        duration_s=time.perf_counter() - start,
        errors=errors,
        library_mode=config.library_mode,
    )


def scan_apk(path: str | Path, config: Config | None = None) -> ScanResult:
    config = config or Config()
    start = time.perf_counter()
    ctx = load_apk(path, exclude_packages=config.exclude_packages)
    result = scan_context(ctx, config)
    result.duration_s = time.perf_counter() - start
    return result
