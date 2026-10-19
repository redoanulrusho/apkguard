## What does this change?

<!-- A short description of the change and why it is needed. Link related issues: "Fixes #123". -->

## How was it tested?

<!-- New or changed tests, manual checks, evaluation results for rule changes. -->

## Checklist

- [ ] `ruff check src tests evaluation` and `ruff format --check src tests evaluation` pass
- [ ] `mypy src evaluation` passes (strict)
- [ ] `pytest` passes, and new behaviour has tests (rules: positive *and* negative cases)
- [ ] New rules have triage guidance in `src/apkguard/guidance.py`
- [ ] User-visible changes are in the `Unreleased` section of `CHANGELOG.md`
- [ ] Changes to `Finding.fingerprint` (which break baselines and SARIF alert tracking) are called out above
- [ ] No APKs other than small, benign F-Droid fixtures with documented SHA-256 are added
