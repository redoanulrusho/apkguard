# Design decisions

Decisions made while building APKGuard autonomously, with the reasoning behind each, so they
can be reviewed and reversed.

## Architecture

1. **Rules never touch androguard.** `loader.py` converts the APK into a plain `ApkContext`
   (lxml manifest tree, simplified `Instruction` lists, strings). Rules and their unit tests
   depend only on that model. *Why:* every rule can be unit-tested with synthetic inputs (the
   brief asked for tests for every rule and allowed synthetic inputs), and an androguard API change
   only affects one file.
2. **One module per rule** (`rules/manifest_debuggable.py`, `rules/code_weak_cipher.py`, ...),
   registered explicitly in `rules/__init__.py`. *Why:* this matches the brief ("each as a separate
   rule module") and keeps the registry explicit and ordered. Plugin discovery via entry points
   is on the roadmap.
3. **Own lightweight bytecode analysis instead of androguard's `Analysis` / xref graph.**
   `analysis.iter_calls` performs one linear pass per method and tracks constants in registers.
   *Why:* building androguard's full analysis is slow on large apps, and the rules mostly need
   "what constant reaches argument N of call X". *Trade-off:* control flow is ignored. A value
   assigned on one branch may be attributed to a call on another branch (seen in practice
   on AndroidX code), and values passed through fields or other methods are not tracked.
4. **Wide (long/double) arguments are not special-cased** when mapping registers to parameter
   positions. All parameters inspected by current rules come before any wide argument, so
   this does not affect results today. It is documented here for future rules.
5. **Instruction refs are normalised** (spaces removed from androguard's descriptor output), so
   rules match `(Ljava/lang/Object;Ljava/lang/String;)V`-style signatures.

## Rules and severities

6. **Severity scale:** info < low < medium < high < critical. Rules may raise or lower severity
   per finding (an exported provider is high, an exported activity low; DES high, AES/ECB medium).
   `critical` is reserved for secrets that are almost always exploitable (private keys, Stripe
   live keys).
7. **AG-MAN-002 (allowBackup)** reports missing `allowBackup` because the platform default is
   `true`. It lowers severity to *low* when backup rules (`fullBackupContent` /
   `dataExtractionRules`) exist, because their content is not inspected yet.
8. **AG-MAN-003 (cleartext)**: a network security config `base-config` overrides the manifest
   attribute (matching platform behaviour on API 24+). `domain-config` exceptions are *low*
   because they are scoped.
9. **AG-MAN-004 (exported)** skips the MAIN/LAUNCHER activity (exported by design). It treats
   custom permissions with `normal`/`dangerous` protection as no protection. Implicit export via
   `<intent-filter>` is reported for any targetSdk, because apps targeting 31+ cannot install
   without explicit `exported` anyway.
10. **AG-MAN-005 thresholds:** recommended targetSdk 34 (*medium* below it, *high* below 28) and
    minSdk 23 (*low*). Play Store requirements move every year, so thresholds are configurable
    via `rule_options` rather than hard-coding the newest level.
11. **AG-PERM-001 is info by default** (dangerous permissions are normal for many apps). High-risk
    special permissions are *medium*. Suspicious *combinations* are a separate rule
    (AG-PERM-002) so they can be gated on independently.
12. **AG-CODE-002 (reflection)** uses a per-class threshold (default 8 calls) and a separate
    note for reflection into hidden platform APIs. That note was first *medium*, then lowered to
    *low* after scanning a real app showed AndroidX itself does this routinely.
13. **AG-CODE-004** also reports `setJavaScriptEnabled(true)` as *info*. It was added after the
    real-APK probe showed it is the most common WebView pattern. It gives reviewers context for
    AG-CODE-003 and exercises the bytecode pipeline in integration tests.
14. **AG-CODE-006 (weak hash):** MD5 is *medium* and SHA-1 *low*, because both are often used for
    non-security checksums. Remediation text explains how to suppress.
15. **AG-SEC-001 (secrets):** Google API keys found in google-services resources
    (`google_api_key`, ...) are downgraded to *low* because they are designed to ship in the APK.
    Generic "secret-looking resource" detection requires a secret-like name, length ≥ 16, no
    spaces, no placeholder words and Shannon entropy ≥ 3.5 to limit false positives.
    **Secrets are always redacted** in output (first 4 and last 2 characters plus length;
    values of 8 characters or fewer are fully masked) so reports and
    SARIF uploads do not leak them further.
16. Code-level secret scanning only looks at `const-string` values in non-excluded classes
    (not the whole DEX string table). That gives a precise method location and respects
    `exclude_packages`.

## CLI, configuration and CI

17. **Default `--fail-on` is `high`.** It is a sensible CI gate, and `none` is available for
    report-only runs. Precedence: CLI flag > config `fail_on` > default.
18. **Exit codes:** 0 pass, 1 threshold exceeded, 2 usage/config error, 3 APK unreadable. Keeping
    "findings" separate from "tool failure" lets CI distinguish a security gate from a broken
    pipeline.
19. **Suppressed findings are kept** in JSON/HTML/SARIF (SARIF `suppressions` with
    justification) but excluded from the threshold and the table (unless `--show-suppressed`).
    *Why:* auditability.
20. **Strict config validation:** unknown keys and unknown rule IDs are errors (exit 2), so a typo
    cannot silently disable a check.
21. **SARIF locations** point at the APK file itself (relative to the working directory, `startLine
    1`), and the in-APK location goes into `logicalLocations` and the message. GitHub requires a
    physical location, and APK-internal paths do not exist in the repository.
    `partialFingerprints` are derived from rule ID + location + evidence for stable
    de-duplication across runs.
22. **The GitHub Action is a composite action** (not Docker), so it runs on Linux, macOS and
    Windows runners. All inputs are passed through `env:` (never interpolated into scripts) to
    avoid script injection. The scan step records the exit code, SARIF is uploaded, and only
    then does a final step fail the job.
23. **The HTML report is a single file with inline CSS/JS** and no external resources. It works
    offline as a CI artifact, and all dynamic content is HTML-escaped (tested with a
    `<script>` payload in a component name).
24. **Terminal output** is 160 columns wide when not attached to a TTY (CI logs, files) instead of
    rich's default 80. Stdout/stderr are reconfigured to UTF-8 so Windows consoles do not crash
    on box-drawing characters.

## Quality and testing

25. **Test fixtures:** four small (90–350 KB) GPL-3.0 apps by Bill Farmer, downloaded unmodified
    from f-droid.org. No malware or APKs from untrusted sources. Hashes and sources are in
    `tests/fixtures/apks/README.md`. Rules that cannot fire on benign apps (TrustManager,
    hardcoded keys, ...) are covered with synthetic Dalvik instruction sequences.
26. **SARIF is validated against the official 2.1.0 JSON schema** (vendored in `tests/fixtures`),
    not just checked for key names.
27. **A meta-test fails if any rule class is not referenced in a rule test module**, which
    enforces "tests for every rule" going forward.
28. **mypy strict** on `src/`. Ruff with E/F/W/I/B/UP/N/SIM/RUF. Line length 100, relaxed for
    tests (long smali signatures).
29. **License: Apache-2.0** (same as androguard). Fixture APKs keep their own GPL-3.0 license and
    are only test data.
30. **Git identity:** session 1 used a placeholder email. In session 2 (2026-10-20) the repo's
    identity was set to `Redoanul Karim Rusho <redoanulkarim1@gmail.com>` and the author *and*
    committer of all 6 existing commits were rewritten with `git filter-branch --env-filter`
    (safe: never pushed). A `git bundle` of the old history was kept in the session scratchpad
    before rewriting, and `refs/original` was removed afterwards so no placeholder remains.

## Session 2: evaluation, library detection, baselines, MCP

31. **Evaluation corpus: 50 F-Droid apps, pinned by SHA-256.** Only `f-droid.org/repo` is used
    (benign, built from source by F-Droid). Selection is mechanical and recorded in
    `evaluation/apks.json` (size 300 KB-6 MB, updated in the last two years, no anti-features,
    one app per category, seeded shuffle) so it cannot be cherry-picked after seeing results.
    APKs are gitignored; `evaluation/fetch_apks.py` (stdlib only) re-downloads and verifies them.
    The raw results (`findings.csv`, `summary.json`) *are* committed so the numbers in
    EVALUATION.md can be checked without re-running.
32. **Manual review labels** distinguish "true positive", "correct but not actionable" and
    "false positive". A plain TP/FP split would hide the main finding of the evaluation: detection is
    accurate, but many correct findings are in library code or describe intended behaviour.
33. **Fixed: constant-bytes source in `analysis.py`.** `s.getBytes("UTF-8")` was treated as the
    constant `"UTF-8"` because any constant argument counted. The source position is now explicit
    per API (receiver for `String` methods, argument for `Base64` decoders). Found via a false
    AG-CODE-007 finding in the evaluation.
34. **Findings are de-duplicated by fingerprint** in the scanner (e.g. the same
    `addJavascriptInterface` call twice in one method). The merged finding carries
    `occurrences`. Fingerprints must be unique per scan for SARIF and baselines to work.
35. **Library detection by package prefix, default `separate`.** Findings whose class (code
    findings) or component (AG-MAN-004) is in a known library package get `Finding.library`.
    Three modes: `separate` (default: kept in reports and SARIF, marked as suppressed there, but
    left out of the summary and the exit code), `include`, `exclude`. *Why separate rather than
    exclude by default:* the evaluation showed that package names can hide a real issue
    (`androidx.test` code shipped in a release build), so nothing is silently discarded. *Why not
    `include`:* a third of all findings were library noise. Precedence: CLI > config > default.
36. **Whole-segment matching, longest prefix wins, the app's own package is never a library.**
    `kotlin` must not match `kotlinapp`, and an app like `com.google.zxing.client.android` must
    not have its own code hidden by the broad `com.google` entry. Permission findings are never
    classified, even though `com.google.android.c2dm.permission.RECEIVE` looks like a package.
37. **`library_packages` extends the built-in list instead of replacing it,** so a project that
    adds one vendored SDK does not lose AndroidX/Kotlin detection. Five built-in entries were
    added after seeing the evaluation; EVALUATION.md reports their effect separately (15 findings).
38. **Separated library findings go into SARIF as `suppressions`** (justification "Third-party
    library code (...)"), the same mechanism as config suppressions. GitHub code scanning then
    keeps them out of the open alerts while the SARIF stays complete for auditing.
39. **No obfuscation-aware library detection.** R8-renamed library classes (`La2;`) are not
    recognised. Fingerprinting library code (LibScout/LibID style) would fix it but is a project of
    its own. The evaluation quantifies the gap (253 remaining findings are in obfuscated classes).
40. **Baselines are matched by fingerprint only, and the file is reviewable.** `--write-baseline`
    stores fingerprint + rule + severity + location per finding, sorted, LF line endings, so
    regenerating an unchanged baseline is a no-op diff and reviewers can see what was accepted.
    `--write-baseline` always exits 0 (creating a baseline *is* accepting the current state).
    Suppressed findings are not written, since the config already accepts them.
41. **Fingerprints were made more stable before the first release** (nothing published yet, so
    no compatibility break): the DEX file number is ignored (`classes2.dex` == `classes.dex`),
    because classes move between DEX files as an app grows, and the reflection rule no longer
    puts the call count in its evidence. Message wording and severity were already excluded.
    Manifest findings have the same fingerprint in every app (e.g. `allowBackup`), which is
    fine because a baseline belongs to one app. The CLI warns on a package mismatch.
42. **Unchanged findings stay in every report** (`baseline_state` in JSON, SARIF's native
    `baselineState`, a tag in HTML) and are only hidden from the terminal table and the gate.
    GitHub code scanning already tracks alert state across runs, so SARIF does not suppress them.
43. **The action takes `baseline` and `library-findings` inputs** through `env:` like every other
    input (no `${{ }}` in scripts). The scan step was executed in Git Bash for no baseline, a
    valid baseline, a missing baseline and an invalid library mode. CI exercises the action
    with a generated baseline.
44. **MCP server on the official SDK v2 (`mcp>=2.3,<3`, `MCPServer`), as the optional `mcp`
    extra.** The core scanner keeps three dependencies; `apkguard-mcp` prints an install hint
    (exit 2) when the extra is missing. v2 renamed `FastMCP` to `MCPServer`; the version is
    capped below 3 because the SDK's API moved between majors before.
45. **Three read-only tools with typed pydantic results:** `scan_apk`, `list_rules`,
    `explain_finding`. The tools are plain functions registered with `add_tool`, so they are unit
    tested directly *and* through the SDK's in-process client and a real stdio subprocess.
    Anticipated failures raise `ToolError` (the model sees the message); argument limits
    (`max_findings` 1-500, severity and mode enums) are in the JSON schema.
46. **`scan_apk` returns app findings only by default** (library findings are counted, not
    listed) and caps the list at 50, most severe first, with a `truncated` flag. *Why:* an
    assistant's context is a scarce resource; 400 AndroidX reflection findings would drown the
    two that matter.
47. **Triage guidance lives in `guidance.py`**, one entry per rule (enforced by a test), written
    from the manual review: how to verify a finding and when it is usually benign.
    `explain_finding` also emits a suppression snippet that is tested to parse as a valid config.
48. **Prompt injection is documented, not "solved".** Findings contain APK-controlled strings.
    The server instructions and README tell clients to treat them as data; the server is
    read-only and has no network access, which limits what an injected instruction could reach
    through APKGuard itself.
49. **Packaging: single-sourced version, PEP 639 license metadata, explicit `lxml`.** The version
    lives only in `apkguard.__version__` (`dynamic = ["version"]`), so `apkguard --version`, the
    SARIF tool version and the package version cannot drift. `license = "Apache-2.0"` with
    `license-files` needs setuptools >= 77 at build time. `lxml` is imported directly, so it is
    declared even though androguard already pulls it in.
50. **The sdist excludes `tests/`, `evaluation/` and `docs/`** (MANIFEST.in). The fixtures are
    third-party GPL APKs and the evaluation needs 300 MB of downloads; both stay in git, where
    contributors get them. The wheel contains only `src/apkguard`.
51. **Repository URLs use the placeholder `YOUR_GITHUB_USER`**, because the GitHub account name is
    not known here. PROGRESS.md gives a one-line command to replace it before publishing.
52. **CI gained a `package` job** that builds, runs `twine check`, installs the wheel (with the
    `mcp` extra) into a fresh venv and smoke-tests it, mirroring the local release check.
53. **Call sites are cached per method (`MethodInfo.call_cache`).** Checking the README claim
    that "rules are cheap" showed it was false: rules took ~50% of scan time, because seven code
    rules each re-ran the register tracking over every method. Computing call sites once cut rule
    time by 3x (8.2 s -> 2.4 s on the slowest app) with byte-identical findings on all 50 apps.
    *Trade-off:* the cache lives on the model object, which is only safe because instructions are
    never modified after loading (documented on `iter_calls`).

