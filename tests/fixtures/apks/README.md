# Test fixture APKs

All APKs here are small, benign, open-source apps by Bill Farmer, downloaded unmodified from the
official F-Droid repository (`https://f-droid.org/repo/<package>_<versionCode>.apk`) on 2026-10-06.
They are licensed under the GNU GPL v3. Source code is available at the linked repositories.

| File | App | Source | SHA-256 |
|---|---|---|---|
| `org.billthefarmer.editor_198.apk` | Editor 1.98 | https://github.com/billthefarmer/editor | `343d17e11d0914e1a7708df2781580a0413e52501c0a41d91f7ef725d9615fe9` |
| `org.billthefarmer.notes_141.apk` | Notes 1.41 | https://github.com/billthefarmer/notes | `ae8aa96794fc55d58916d8fe3a217912fbcc9edd5ec9fb72c547f90d97d3c0ea` |
| `org.billthefarmer.tuner_158.apk` | Tuner 1.58 | https://github.com/billthefarmer/tuner | `7fbfaee87f3402f7c4b269ac42a36a2ff2c91b382655647efad23d631caff944` |
| `org.billthefarmer.diary_1105.apk` | Diary 1.105 | https://github.com/billthefarmer/diary | `979e8cd8702ab5c0440c2cd094de0d6bdf109632857002966e62af5e9add93ef` |

They were picked because they are tiny (90–350 KB), so tests stay fast. None of them is malware,
and APKGuard findings on them are ordinary hardening suggestions, not vulnerabilities.

To re-download a fixture:

```bash
curl -LO https://f-droid.org/repo/org.billthefarmer.editor_198.apk
```

Rules that never fire on these apps (insecure TrustManager, hardcoded keys, etc.) are covered
by unit tests built from synthetic manifests and Dalvik instructions (`tests/helpers.py`).
