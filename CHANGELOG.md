# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-20

First public release.

### Added

- `apkguard scan app.apk`: static analysis of Android APKs with androguard, with 17 rules across
  manifest, permissions, bytecode and hardcoded secrets. Every rule has an ID, severity, CWE,
  OWASP MASVS mapping, description, remediation and references (`apkguard rules`).
- Output formats: terminal table, JSON, SARIF 2.1.0 (validated against the official schema,
  GitHub code scanning compatible) and a self-contained HTML report.
- CI-friendly exit codes (`0` pass, `1` findings at or above `--fail-on`, `2` usage or
  configuration error, `3` unreadable APK).
- `.apkguard.yml` configuration: disable rules, severity overrides, suppressions with reasons,
  package excludes, rule options, strict validation of keys and rule IDs.
- Third-party library detection: findings in AndroidX, Kotlin, Google, OkHttp and other common
  libraries are reported separately and do not fail the build by default
  (`--library-findings separate|include|exclude`, `--library-package`).
- Baselines: `--write-baseline FILE` accepts the current findings, `--baseline FILE` fails only
  on new ones. JSON, SARIF (`baselineState`), HTML and terminal output show new/unchanged.
- GitHub Action (composite, runs on Linux/macOS/Windows runners) with SARIF upload to code
  scanning, `baseline` and `library-findings` inputs.
- MCP server (`pip install "apkguard[mcp]"`, `apkguard-mcp`) with `scan_apk`, `list_rules` and
  `explain_finding` tools for Claude Desktop, Claude Code and other MCP clients.
- Per-rule triage guidance (how to verify, when a finding is usually benign).
- Dockerfile, CI workflow (lint, strict typing, tests on Linux/Windows/macOS, Python 3.10-3.13,
  Docker build, action self-test).
- Real-world evaluation on 50 F-Droid apps with a manual review of findings
  ([EVALUATION.md](EVALUATION.md)), reproducible from pinned SHA-256 hashes.

### Fixed (found during the evaluation)

- A string's `getBytes("UTF-8")` was treated as the hardcoded constant `"UTF-8"`, producing a false
  "hardcoded key" finding.
- Identical findings from two call sites in one method were reported twice with the same
  fingerprint; they are now merged with an `occurrences` count.
- Fingerprints no longer change when a class moves to another `classesN.dex` file, or when a
  class gains one more reflective call.

[Unreleased]: https://github.com/YOUR_GITHUB_USER/apkguard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/YOUR_GITHUB_USER/apkguard/releases/tag/v0.1.0
