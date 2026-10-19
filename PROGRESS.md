# PROGRESS

## Summary (end of autonomous session, 2026-10-06)

**Status:** all six requested features are implemented, tested and committed locally (no
remote, nothing pushed).

### Completed features
| # | Feature | Status |
|---|---|---|
| 1 | `apkguard scan app.apk` CLI on androguard | ✅ Done (`scan` and `rules` subcommands) |
| 2 | Rules, one module each, with ID/severity/description/remediation (+ CWE, MASVS, references) | ✅ 17 rules: 5 manifest, 2 permissions, 9 code, 1 secrets |
| 3 | Terminal table, JSON, SARIF 2.1.0, standalone HTML | ✅ Done. SARIF validated against the official schema |
| 4 | Exit codes and `--fail-on` threshold | ✅ 0 pass / 1 findings ≥ threshold / 2 usage-config error / 3 unreadable APK |
| 5 | Config file: disable rules, suppress findings | ✅ `.apkguard.yml` also supports severity overrides, package excludes, rule options and strict validation |
| 6 | GitHub Action (`action.yml`) | ✅ Composite action: SARIF upload to code scanning, then threshold enforcement |
| Q | pyproject, type hints, ruff, pytest for every rule, Dockerfile, CI workflow, README | ✅ Done |

### Test results (run on this machine)
- **177 tests passed, 0 failed**, on Windows 11 / Python 3.11.6 (`pytest`, ~5 s). Line coverage is
  **97%** (`pytest --cov=apkguard`).
- **177 passed** on Linux (WSL Ubuntu) / Python 3.10.22, the minimum supported version.
- `ruff check` ✅, `ruff format --check` ✅, `mypy --strict src` ✅ (34 files, no issues).
- Wheel build plus install into a clean Linux venv, then `apkguard scan` on a fixture: ✅ (the same
  steps the Dockerfile runs).
- The action's scan step (extracted from `action.yml`) was run in Linux bash. Exit code
  propagation was verified for pass, fail and error cases.
- Real-world check: a 3.5 MB F-Droid app (Shader Editor, 2,456 classes) scans in about 4.5 s.

### Known limitations
- **Docker image not built or tested.** Docker isn't installed on this machine. The Dockerfile
  mirrors the wheel build/install that *was* tested. CI has a `docker` job that builds it and
  smoke-tests it.
- **GitHub workflows (`ci.yml`, `action.yml`) have not run on GitHub**, because the brief said not to create a
  repo or push. They are YAML-validated by tests, and the action's shell logic was executed locally.
- **Bytecode analysis is intra-procedural and ignores control flow.** Constants passed through
  fields or other methods are missed, and branch-merged registers can occasionally be
  mis-attributed. See DECISIONS.md #3.
- Code rules that cannot fire on benign apps (TrustManager, HostnameVerifier, hardcoded keys,
  dynamic loading, `addJavascriptInterface`, weak crypto) are tested **only with synthetic
  Dalvik instruction sequences**, not real compiled malware-like samples. That was deliberate (no
  untrusted APKs). The real-APK pipeline itself is verified end to end with `setJavaScriptEnabled`
  in the Diary fixture.
- No real F-Droid fixture contains a `networkSecurityConfig`. That loader path is tested with a fake
  APK object (and a bug was found and fixed that way).
- Findings in third-party libraries are reported like app code unless `exclude_packages` is
  used. There is no automatic library detection yet.
- The `uses: apkguard/apkguard@v0.1.0` reference in the README and examples is a placeholder until
  the action is published somewhere.
- The git commits use the existing local identity `Redoan Rusho <your_github_email@example.com>`.
  The email is a placeholder. Fix with `git config user.email you@example.com`, and rewrite
  history before publishing if needed.

### Suggested next steps
1. Push to a GitHub repo and let `ci.yml` run (Linux/Windows/macOS matrix, Docker, action self-test).
2. Add `--baseline <file>` so PRs fail only on *new* findings (fingerprints already exist).
3. Library detection, so third-party findings are separated or skipped by default.
4. More rules: mutable `PendingIntent`, `MODE_WORLD_READABLE`, `rawQuery` SQL injection, logging
   of secrets, `FileProvider` root paths, native library hardening, user-trusted CAs in the network
   security config.
5. Publish to PyPI and GHCR, and tag `v0.1.0` so the action can be referenced.

---

## Session 2 log (2026-10-20)

### Step 0 - git identity and baseline
- Repo identity set to `Redoanul Karim Rusho <redoanulkarim1@gmail.com>`; all 6 commits rewritten
  (author + committer). `git log --all --format='%ae%n%ce' | grep -c your_github_email` -> `0`.
- Baseline quality gate (Windows 11, Python 3.11.6): ruff ✅, ruff format ✅ (47 files),
  mypy --strict ✅ (34 files), **177 passed**, coverage **97%** (1527 statements, 46 missed).

### Step 1 - real-world evaluation
- 50 F-Droid apps (pinned list + SHA-256 in `evaluation/apks.json`, downloader
  `evaluation/fetch_apks.py`, runner `evaluation/run_evaluation.py`; APKs gitignored).
- 50/50 scanned, no rule errors; median 7.5 s per APK, max 16.5 s; 737 findings, 63% from the
  reflection rule. Manual review of 23 findings: 8 TP, 13 correct-but-not-actionable, 2 FP.
- Review found and fixed a real bug (`getBytes("UTF-8")` treated as a constant key, DECISIONS
  #33) and duplicate fingerprints (#34). Write-up: EVALUATION.md.

### Step 2 - library detection
- `src/apkguard/libraries.py`, `--library-findings separate|include|exclude` (default separate),
  `--library-package`, config `library_findings` / `library_packages`. Reported in JSON
  (`origin`, `library`, summary block), SARIF (suppressed), HTML (tag), terminal (one-line note).
- Evaluation: 737 -> 492 findings (-33%), code findings -47%, high 19 -> 14, apps failing the
  default gate 12 -> 10; both reviewed FPs leave the gate, one TP (`androidx.test`) is separated.
- 19 new tests (199 total), coverage 97%.

### Step 3 - baseline mode
- `src/apkguard/baseline.py`; `--write-baseline FILE` (exit 0) and `--baseline FILE` (only new
  findings gate). JSON/SARIF/HTML/terminal show new vs unchanged and count fixed entries.
- Fingerprints hardened (DEX number ignored, no call count in reflection evidence).
- Action inputs `baseline` and `library-findings`; the scan step was executed locally in bash for
  all cases; CI runs the action against a generated baseline. 17 new tests.

### Step 4 - MCP server
- `pip install "apkguard[mcp]"`, command `apkguard-mcp` (stdio). Tools `scan_apk`, `list_rules`,
  `explain_finding` with typed output schemas and read-only annotations.
- 17 tests: tool functions, in-process MCP client, and a real stdio subprocess. The installed
  `apkguard-mcp.exe` was also driven over stdio against an evaluation APK.
- Not verified here: Claude Desktop / Claude Code themselves (not installed on this machine);
  the README documents the standard configuration for both.

## How to run

```powershell
# from D:\thesis\apkguard
python -m venv .venv
.\.venv\Scripts\pip install -e ".[dev]"

# scan
.\.venv\Scripts\apkguard scan tests\fixtures\apks\org.billthefarmer.notes_141.apk
.\.venv\Scripts\apkguard scan app.apk --fail-on medium --sarif out.sarif --html out.html --json out.json
.\.venv\Scripts\apkguard scan app.apk --format json            # JSON to stdout
.\.venv\Scripts\apkguard scan app.apk --config examples\.apkguard.yml
.\.venv\Scripts\apkguard rules                                  # list rules

# quality gate (what CI runs)
.\.venv\Scripts\ruff check src tests
.\.venv\Scripts\ruff format --check src tests
.\.venv\Scripts\mypy src
.\.venv\Scripts\pytest --cov=apkguard
```

Linux/macOS: replace `.\.venv\Scripts\` with `.venv/bin/`.

Docker (not verified locally, see limitations):

```bash
docker build -t apkguard .
docker run --rm -v "$PWD:/work" apkguard scan app.apk --html report.html
```

## What works (verified)
- Parsing of real APKs: manifest, all DEX files, resource strings, text assets, and the network security
  config (resolved via resource ID, with fallback).
- All 17 rules, with positive and negative unit tests (a meta-test enforces this).
- Expected findings on the F-Droid fixtures: cleartext in Notes, allowBackup / exported shortcut
  activities / minSdk 21 in Editor, targetSdk 28 and WebView JavaScript in Diary. Launcher
  activities are correctly not flagged.
- Config: disable, severity overrides, suppressions (kept in reports, excluded from the
  threshold), `exclude_packages`, `rule_options` with validation, and `fail_on` precedence (CLI > config >
  default `high`).
- Reports: JSON, SARIF (schema-valid, stable fingerprints, suppressions, rule help and
  security-severity for GitHub), HTML (self-contained, escaped, filterable, dark mode), and a terminal
  table.
- Secrets are redacted in all outputs.

## Milestone log (git)
1. `Add core scanner, 17 rules, reporters and CLI`
2. `Add test suite: unit tests per rule, reporters, config, CLI and F-Droid fixtures`, which also
   fixed google-services keys not being downgraded
3. `Add GitHub Action, Dockerfile, CI workflow and example config`
4. `Add README, DECISIONS, sample reports; fix plain-XML network security config parsing`
5. `Fix fail_on: none in config being ignored; validate rule_options`
6. `Add PROGRESS.md` (this file)

## Project layout
```
src/apkguard/
  cli.py          argparse CLI, exit codes
  loader.py       androguard -> ApkContext (only androguard-aware module)
  context.py      Manifest / ClassInfo / MethodInfo / Instruction model
  analysis.py     per-method constant tracking (call sites + argument values)
  scanner.py      runs rules, applies config
  config.py       .apkguard.yml parsing/validation
  model.py        Severity, Finding, RuleMeta, Location
  rules/          one module per rule (+ base.py, _util.py, registry in __init__.py)
  reporters/      terminal.py, json_report.py, sarif.py, html.py
tests/
  unit/           rule tests (synthetic), analysis, config, scanner, reporters, loader helpers
  integration/    real F-Droid APKs + CLI end-to-end
  fixtures/       4 F-Droid APKs (see README there), SARIF 2.1.0 schema
action.yml, Dockerfile, .github/workflows/ci.yml, examples/, docs/ (sample reports)
```
