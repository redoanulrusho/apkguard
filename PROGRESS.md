# PROGRESS

## Summary (end of session 2, 2026-10-20)

**Status:** all seven requested steps (0-6) are done, tested and committed locally. Nothing was
pushed, no GitHub repository was created, nothing was published.

### What was completed

| Step | Result |
|---|---|
| 0 Git identity | All commits authored and committed as `Redoanul Karim Rusho <redoanulkarim1@gmail.com>` (history rewritten; 0 placeholder emails left). Baseline gate recorded: 177 tests, 97%. |
| 1 Evaluation | 50 F-Droid apps (pinned by SHA-256, `evaluation/`), 50/50 scanned, 737 findings, manual review of 23 findings -> [EVALUATION.md](EVALUATION.md). Found and fixed 2 bugs. |
| 2 Library detection | `--library-findings separate/include/exclude` (default `separate`), `--library-package`, config keys. -33% findings, -47% code findings, high 19 -> 14. |
| 3 Baselines | `--write-baseline` / `--baseline`, new/unchanged in all reports, action inputs `baseline` and `library-findings`, CI self-test. Evaluated on 42 real release pairs. |
| 4 MCP server | `pip install "apkguard[mcp]"`, `apkguard-mcp` (stdio), tools `scan_apk`, `list_rules`, `explain_finding`; tested in-process and over a real stdio subprocess. |
| 5 Release readiness | v0.1.0 (single-sourced), full metadata, CHANGELOG, CONTRIBUTING, SECURITY, issue forms, PR template, `package` CI job. Wheel + sdist built, `twine check` passed, fresh-venv install verified. |
| 6 README | Real example output, evaluation summary, rules table with hit counts, baseline + MCP usage, Mermaid architecture, limitations, roadmap. |
| Extra | Performance: rules were ~50% of scan time; caching call sites cut the median scan from 7.5 s to 5.4 s with byte-identical findings. CLI reports now use LF on every platform. |

### Test and coverage results (final code, commit `4373ca4`)

- Windows 11 / Python 3.11.6: **236 passed**, coverage **97%** (1870 statements, 49 missed);
  `ruff check` ✅, `ruff format --check` ✅ (59 files), `mypy --strict` ✅ (41 files: `src` +
  `evaluation`).
- Linux (WSL Ubuntu) / Python 3.10.22, the minimum version, tests run against the **installed
  wheel** (`apkguard[mcp]` from `dist/`, imported from site-packages, not `src/`): **236 passed** ✅.
- Wheel `apkguard-0.1.0-py3-none-any.whl` installed into a fresh venv: `--version`, `rules`,
  `scan` with SARIF/HTML, exit codes, `apkguard-mcp` with and without the `[mcp]` extra ✅.
- The action's scan step (bash) was executed locally for: no baseline, baseline, missing
  baseline, invalid library mode ✅.

### Evaluation highlights (details in EVALUATION.md)

- 50/50 APKs scanned, no rule errors; median 5.4 s per APK, max 13.2 s.
- 737 findings; 63% were the reflection rule, mostly in AndroidX. Library detection moves 33% of
  findings out of the gate; 253 remaining "app" findings sit in R8-obfuscated classes.
- Manual review of 23 findings: 8 true positives (e.g. a hostname verifier that accepts every
  certificate, a trust-all TrustManager, a shipped API secret, `androidx.test` code in a
  release), 13 correct but not actionable, 2 false positives (Cordova code behind a condition).
- Bugs found and fixed: `password.getBytes("UTF-8")` reported as a hardcoded key; duplicate
  fingerprints.
- Baselines across 42 real upgrades: 75% of findings matched, 19 apps had zero new findings,
  1/42 upgrades would fail the default gate. About 95% of "new" findings were R8 renames.

### Known issues and limitations

- **Not run on GitHub.** CI (`ci.yml`, now with a `package` job and a baseline action test) and
  the composite action have never run on GitHub-hosted runners. Their YAML is validated by tests
  and the action's shell step was executed locally.
- **Docker image still not built** (Docker is not installed here). The CI `docker` job will be
  its first build.
- **Claude Desktop / Claude Code were not available on this machine**, so the documented
  configuration (`claude mcp add apkguard -- apkguard-mcp`, `claude_desktop_config.json`) was not
  tried in those apps. The exact launch they perform (the `apkguard-mcp` executable over stdio)
  was tested.
- **Repository URLs point to `github.com/redoanulrusho/apkguard`**, which does not exist yet.
  README badges, the SARIF `informationUri`, the `pyproject.toml` URLs and the action reference
  `redoanulrusho/apkguard@v0.1.0` only resolve once the repository is pushed and tagged.
- Analysis limits (README "Limitations"): flow-insensitive and intra-procedural; package-name
  library detection does not see through R8 renaming, which also causes baseline churn in
  obfuscated apps; severity is per pattern.
- The manual review is one reviewer and 23 findings, so the TP/FP rates are rough estimates.
- `evaluation/apks/` (92 APKs, ~320 MB) is local only and gitignored. Delete it any time and
  re-create it with `python evaluation/fetch_apks.py`.

### How to publish it yourself

1. **Repository URLs:** done. Every former GitHub-user placeholder now reads `redoanulrusho`
   (session 3).
2. **Create the GitHub repository** `redoanulrusho/apkguard` (public, empty: no README, no
   .gitignore, no license), then:
   ```bash
   git branch -M main
   git remote add origin https://github.com/redoanulrusho/apkguard.git
   git push -u origin main
   ```
3. **First CI run:** open the *Actions* tab and check that `CI` passes (lint, tests on
   Linux/Windows/macOS and Python 3.10-3.13, package, docker, action). Fix anything
   platform-specific it finds. Under *Settings → Code security*, enable *Private vulnerability
   reporting* (SECURITY.md links to it).
4. **Tag v0.1.0** once CI is green:
   ```bash
   git tag -a v0.1.0 -m "APKGuard 0.1.0"
   git push origin v0.1.0
   ```
   Create a GitHub release from the tag and paste the 0.1.0 section of CHANGELOG.md.
5. **PyPI:** check that the name `apkguard` is still free (if not, change `name` in
   `pyproject.toml`; the import name and command can stay `apkguard`). Create an API token (or set
   up Trusted Publishing for the repository), then:
   ```bash
   rm -rf dist && python -m build && python -m twine check dist/*
   python -m twine upload --repository testpypi dist/*   # optional dry run
   python -m twine upload dist/*
   ```
6. **GitHub Marketplace:** the repository root already has `action.yml` with name, description and
   branding. On the v0.1.0 release page, tick *Publish this Action to the GitHub Marketplace*
   (accept the developer agreement; the action name must be unique on the Marketplace). Users
   then write `uses: redoanulrusho/apkguard@v0.1.0`.

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

### Step 5 - release readiness
- Version 0.1.0 single-sourced; full metadata (author, PEP 639 license, classifiers, URLs,
  keywords); CHANGELOG, CONTRIBUTING, SECURITY, 3 issue forms + config, PR template.
- `python -m build` -> wheel (45 files) + sdist (no tests/APKs); `twine check` PASSED.
- Fresh venv (Python 3.11.6): wheel install, `apkguard --version/rules/scan` with SARIF+HTML,
  exit codes as expected; `apkguard-mcp` without the extra prints the install hint (exit 2); with
  `[mcp]` it serves over stdio. Nothing was published.

## How to run

```powershell
# from D:\thesis\apkguard
python -m venv .venv
.\.venv\Scripts\pip install -e ".[dev]"

# scan
.\.venv\Scripts\apkguard scan tests\fixtures\apks\org.billthefarmer.notes_141.apk
.\.venv\Scripts\apkguard scan app.apk --fail-on medium --sarif out.sarif --html out.html --json out.json
.\.venv\Scripts\apkguard scan app.apk --library-findings include      # also list library findings
.\.venv\Scripts\apkguard scan app.apk --write-baseline baseline.json  # accept current findings
.\.venv\Scripts\apkguard scan app.apk --baseline baseline.json        # fail only on new ones
.\.venv\Scripts\apkguard rules
.\.venv\Scripts\apkguard-mcp                                         # MCP server over stdio

# quality gate (what CI runs)
.\.venv\Scripts\ruff check src tests evaluation
.\.venv\Scripts\ruff format --check src tests evaluation
.\.venv\Scripts\mypy src evaluation
.\.venv\Scripts\pytest --cov=apkguard

# evaluation (downloads ~320 MB from f-droid.org, verified by SHA-256)
.\.venv\Scripts\python evaluation\fetch_apks.py
.\.venv\Scripts\python evaluation\run_evaluation.py
.\.venv\Scripts\python evaluation\run_baseline_eval.py

# release artefacts (not published)
.\.venv\Scripts\python -m build
.\.venv\Scripts\python -m twine check dist/*
```

Linux/macOS: replace `.\.venv\Scripts\` with `.venv/bin/`.

## Milestone log (git)

Session 1:
1. `Add core scanner, 17 rules, reporters and CLI`
2. `Add test suite: unit tests per rule, reporters, config, CLI and F-Droid fixtures`
3. `Add GitHub Action, Dockerfile, CI workflow and example config`
4. `Add README, DECISIONS, sample reports; fix plain-XML network security config parsing`
5. `Fix fail_on: none in config being ignored; validate rule_options`
6. `Add PROGRESS.md with final summary, test results and run instructions`

Session 2:
7. `Record git identity rewrite and session 2 baseline`
8. `Add real-world evaluation on 50 F-Droid apps; fix constant-bytes tracking and duplicate findings`
9. `Separate findings in third-party libraries from app code`
10. `Add baseline mode so CI fails only on new findings`
11. `Add MCP server with scan_apk, list_rules and explain_finding tools`
12. `Prepare 0.1.0 release: packaging metadata, community files, package CI job`
13. `Cache call sites per method (3x faster rules); write reports with LF endings`
14. `Rewrite README with real output and evaluation results; evaluate baselines across releases`
15. `Update PROGRESS.md with the session 2 summary and publishing steps`

## Project layout
```
src/apkguard/
  cli.py          argparse CLI, exit codes, apkguard-mcp entry point
  loader.py       androguard -> ApkContext (only androguard-aware module)
  context.py      Manifest / ClassInfo / MethodInfo / Instruction model
  analysis.py     per-method constant tracking (cached call sites + argument values)
  scanner.py      runs rules, de-duplicates, applies config, tags library findings
  libraries.py    third-party library detection and modes
  baseline.py     baseline files and new/unchanged comparison
  guidance.py     per-rule triage advice
  mcp_server.py   MCP tools (optional extra)
  config.py       .apkguard.yml parsing/validation
  model.py        Severity, Finding (fingerprint), RuleMeta, Location
  rules/          one module per rule (+ base.py, _util.py, registry in __init__.py)
  reporters/      terminal.py, json_report.py, sarif.py, html.py
tests/            unit (synthetic), integration (F-Droid fixtures, CLI), MCP, baseline, libraries
evaluation/       apks.json (pinned), fetch_apks.py, run_evaluation.py, run_baseline_eval.py, results/
action.yml, Dockerfile, .github/ (CI, issue forms, PR template), examples/, docs/ (sample reports)
```

---

<details>
<summary>Session 1 summary (2026-10-06), kept for history</summary>

> **Superseded.** This is the state at the end of session 1. The current status is the session 2
> summary at the top of this file. Items that later sessions resolved are marked *[resolved]*
> below; the test counts here (177 tests) are from session 1.

### Summary (end of autonomous session, 2026-10-06)

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
- *[resolved in session 2: library detection, `--library-findings`]* Findings in third-party
  libraries were reported like app code unless `exclude_packages` was used.
- *[resolved in session 3: `redoanulrusho/apkguard@v0.1.0`]* The action reference in the README
  and examples was a placeholder.
- *[resolved in session 2: all commits rewritten to `redoanulkarim1@gmail.com`]* The git commits
  used a placeholder email.

### Suggested next steps
1. Push to a GitHub repo and let `ci.yml` run (Linux/Windows/macOS matrix, Docker, action self-test).
2. *[done in session 2]* Add `--baseline <file>` so PRs fail only on *new* findings.
3. *[done in session 2]* Library detection, so third-party findings are separated or skipped by
   default.
4. More rules: mutable `PendingIntent`, `MODE_WORLD_READABLE`, `rawQuery` SQL injection, logging
   of secrets, `FileProvider` root paths, native library hardening, user-trusted CAs in the network
   security config.
5. Publish to PyPI and GHCR, and tag `v0.1.0` so the action can be referenced.

---


</details>
