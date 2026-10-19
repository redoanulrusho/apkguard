# Contributing to APKGuard

Thanks for taking the time to contribute! Bug reports, false-positive reports, new rules and
documentation fixes are all welcome.

## Ground rules

- **Never attach malware or APKs you are not allowed to share** to issues or pull requests. For
  a false positive in a public app, link to its F-Droid or source page instead. For anything
  else, a minimal, synthetic reproduction is best (see "Writing tests").
- Security vulnerabilities in APKGuard itself go through [SECURITY.md](SECURITY.md), not
  public issues.
- Be kind. Assume good intent.

## Development setup

```bash
git clone https://github.com/YOUR_GITHUB_USER/apkguard.git
cd apkguard
python -m venv .venv
. .venv/bin/activate              # Windows: .venv\Scripts\activate
pip install -e ".[dev]"           # includes the MCP extra, build and twine
```

## Quality gate

CI runs exactly these commands, and a pull request should pass all of them:

```bash
ruff check src tests evaluation
ruff format --check src tests evaluation
mypy src evaluation               # strict mode
pytest --cov=apkguard             # unit + integration tests; keep coverage at ~95%+
```

## Adding a rule

1. Create `src/apkguard/rules/<category>_<name>.py` with a `Rule` subclass and a `RuleMeta`
   (ID, title, default severity, description, remediation, references, CWE, MASVS).
2. Register it in `ALL_RULES` in `src/apkguard/rules/__init__.py`.
3. Add triage guidance (how to verify, when it is usually benign) to
   `src/apkguard/guidance.py`. A test fails if a rule has none.
4. Add positive *and* negative unit tests in `tests/unit/test_rules_<category>.py`. A meta-test
   fails if a rule class is not referenced by a rule test.
5. Run the evaluation if you can (`python evaluation/fetch_apks.py && python
   evaluation/run_evaluation.py`) and mention in the PR how many findings the rule produces on
   the 50 F-Droid apps. A rule that fires on most benign apps needs a very good reason.

Rules work on the androguard-independent model in `context.py` (manifest tree, simplified
instructions, strings). They must not import androguard; only `loader.py` does.

## Writing tests

- Build synthetic inputs with the helpers in `tests/helpers.py` (`manifest(...)`, `ctx(...)`,
  `invoke(...)`, `const_string(...)`, ...). This tests rules without real APKs.
- Only benign, open-source APKs from f-droid.org may be added as fixtures. Record the source
  URL, license and SHA-256 in `tests/fixtures/apks/README.md`, and keep them small.

## Reporting a false positive

Use the *False positive* issue template and include the rule ID, the finding's location and
evidence (from the JSON report), and why you believe it is wrong. False-positive reports are
the most useful feedback for a static analyser, and they are how the bugs listed in
[EVALUATION.md](EVALUATION.md) were found.

## Commits and pull requests

- Keep pull requests focused, and describe the change and how you tested it (the PR template
  has a checklist).
- Add a line to the `Unreleased` section of [CHANGELOG.md](CHANGELOG.md) for user-visible
  changes.
- Changing what goes into `Finding.fingerprint` breaks users' baselines and SARIF alert
  tracking. Call it out explicitly in the PR and the changelog.

## Releasing (maintainers)

1. Update the version in `src/apkguard/__init__.py` and move the `Unreleased` changelog entries
   under the new version.
2. `python -m build && python -m twine check dist/*`
3. Tag `vX.Y.Z`, push the tag, publish the GitHub release and upload to PyPI.
