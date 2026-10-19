# Real-world evaluation

APKGuard was run on 50 benign open-source apps from the official F-Droid repository to answer
four questions: does it run reliably on real APKs, how fast is it, how useful are its findings,
and do baselines hold up across real releases? This document reports the results as measured, including the weak spots.

## Setup

| | |
|---|---|
| Source | `https://f-droid.org/repo/` only (official F-Droid repository). No other source, no malware. |
| Selection | Latest version of each app, APK size 300 KB – 6 MB, updated in the last two years, no F-Droid anti-features, one app per primary category (seeded shuffle, seed `20261020`). Full rule in [`evaluation/apks.json`](evaluation/apks.json). |
| Apps | 50 apps from 50 different categories (e.g. browser, email, launcher, keyboard, password vault, podcast player, games). Median size 3.2 MB, 163 MB in total. |
| Integrity | Every APK is pinned by file name and SHA-256 in `evaluation/apks.json`; the downloader deletes any file whose hash differs. |
| Configuration | Default rules and options, no config file. |
| Machine | Windows 11, Python 3.11.6, androguard 4.1.4, single process. |

Reproduce:

```bash
python evaluation/fetch_apks.py          # downloads + verifies 92 APKs (50 current + 42 previous releases)
python evaluation/run_evaluation.py      # writes evaluation/results/{findings.csv,summary.json,summary.md}
python evaluation/run_baseline_eval.py   # writes evaluation/results/baseline_pairs.{json,md}
```

## Reliability and speed

- **50 of 50 APKs scanned**, no crashes, and no rule raised an exception.
- **Runtime per APK: median 5.4 s, mean 5.7 s, 90th percentile 9.7 s, max 13.2 s.** All 50
  together took 4.8 minutes.
- Runtime grows with the amount of bytecode, not the APK size: an icon pack with 4 MB of images
  scans in 0.1 s, while the five apps that take 11-13 s each contain 6,900-8,700 classes.
- **Where the time goes.** Measuring six of the larger apps showed that, in the first version,
  the rules took about half of the scan time: seven code rules each repeated the constant
  tracking over every method. Caching the call sites per method (DECISIONS.md #53) cut rule time
  about 3x (8.2 s → 2.4 s on the FTPS server app, 8,700 classes) and the median scan from 7.5 s to
  5.4 s, with byte-identical findings on all 50 apps. Most of the remaining time is androguard
  parsing the DEX files and the conversion into APKGuard's model.

## Findings per rule

737 findings in total (median 12 per app, between 2 and 38), counting library code too
(`--library-findings include`; the default view is in [Library detection](#library-detection)). By severity: 19 high, 75 medium,
550 low, 93 info, 0 critical.

| Rule | What it checks | Findings | Apps |
|---|---|---:|---:|
| AG-CODE-002 | Reflection-heavy code | 467 | 45 |
| AG-PERM-001 | Dangerous permissions | 100 | 33 |
| AG-MAN-004 | Exported components | 63 | 22 |
| AG-MAN-002 | `allowBackup` | 37 | 37 |
| AG-MAN-005 | Outdated target/min SDK | 18 | 14 |
| AG-CODE-004 | Insecure WebView settings | 13 | 7 |
| AG-CODE-006 | Weak hash (MD5/SHA-1) | 13 | 7 |
| AG-MAN-003 | Cleartext traffic | 9 | 9 |
| AG-CODE-003 | `addJavascriptInterface` | 7 | 3 |
| AG-CODE-001 | Dynamic code loading | 3 | 1 |
| AG-CODE-008 | Insecure TrustManager | 2 | 2 |
| AG-PERM-002 | Suspicious permission combination | 2 | 2 |
| AG-CODE-005 | Weak cipher | 1 | 1 |
| AG-CODE-009 | Insecure HostnameVerifier | 1 | 1 |
| AG-SEC-001 | Hardcoded secret | 1 | 1 |
| AG-MAN-001, AG-CODE-007 | `debuggable`, hardcoded key | 0 | 0 |

Per-app numbers are in [`evaluation/results/summary.md`](evaluation/results/summary.md) and every
finding is in [`evaluation/results/findings.csv`](evaluation/results/findings.csv).

**The reflection rule dominates: 467 of 737 findings (63%).** Nearly all of them are classes that
use reflection with *constant* names. Most are in AndroidX, Kotlin and other libraries (AndroidX
alone accounts for 185), and many more are in R8-obfuscated code (`Lq/f;`, `Ly1;`),
which is usually library code too. These findings are correct as descriptions of the code, but
they are almost never something an app developer can or should act on. See
[Library detection](#library-detection) for how this noise is handled.

## Manual review

I reviewed **23 findings** by hand, looking at the decompiled bytecode or the manifest for each.
The sample is deliberately weighted towards high and medium severity (all the rare
high-severity code findings, plus a seeded random sample of the frequent rules), because those
are the findings that would fail a CI build. Each finding got one of three labels:

- **TP (true positive):** the weakness is really there and worth fixing or reviewing in this app.
- **Correct, not actionable:** the code or manifest really does what the finding says, but in
  context it is not a security problem (protocol-mandated, by design, library internals).
- **FP (false positive):** the finding is wrong, or the flagged code cannot run in a release build.

| # | App | Rule | Finding | Verdict | Why |
|---|---|---|---|---|---|
| 1 | Hauk | AG-CODE-009 | `InsecureHostnameVerifier.verify()` always returns true | TP | Confirmed in bytecode (`const/4 v0, 1; return v0`). The class name suggests an opt-in feature for self-signed servers, but the weakness is real. |
| 2 | OpenContacts | AG-CODE-008 | `NetworkUtils$1.checkServerTrusted()` is empty | TP | Trust-all `X509TrustManager` in app code. |
| 3 | OpenContacts | AG-MAN-004 | `DataSourceService` exported, custom action, no permission | TP | Any app can start or bind to the contacts app's data service; needs review. |
| 4 | Play NotePad | AG-MAN-004 | `androidx.test...BootstrapActivity` exported | TP | Test-only library code shipped in a release build. |
| 5 | pOT-Droid | AG-MAN-004 | `CacheContentProvider` exported without permission | TP | Correct, but *lower* impact than its "high" severity: `openFile` maps the URI to an MD5 cache key, so there is no path traversal, and it only serves cached forum images. |
| 6 | pOT-Droid | AG-CODE-003 | JavaScript bridge `"api"` on a WebView | TP | Forum HTML is rendered in a WebView with a Java bridge; worth reviewing what the bridge exposes. |
| 7 | Homer Audio Player | AG-SEC-001 | `string/podcastindex_secret` (40 chars) | TP | A real third-party API secret shipped in the APK. |
| 8 | LRC Editor | AG-MAN-002 | `allowBackup="true"` with no backup rules | TP | Correct hardening finding (low impact: the app stores lyrics). |
| 9 | Nextcloud News | AG-MAN-003 | `usesCleartextTraffic="true"` | Correct, not actionable | Client for self-hosted servers, so plain HTTP on a LAN is a deliberate feature. |
| 10 | Nextcloud News | AG-MAN-004 | `OwnCloudSyncService` exported | Correct, not actionable | Sync adapter services must be exported for the system `SyncManager`. |
| 11 | DumberKit Calculator | AG-MAN-004 | `FossifyBroadcastReceiver` exported | Correct, not actionable | Shares theme settings between Fossify apps by design. |
| 12 | pOT-Droid | AG-CODE-006 | `MessageDigest.getInstance("MD5")` | Correct, not actionable | Used to name cache files, not for security. |
| 13 | FTPS Server | AG-CODE-008 | BouncyCastle `JcaJceUtils$1.checkServerTrusted()` is empty | Correct, not actionable | Library helper inside BouncyCastle, not app code. |
| 14 | SimpleEmail | AG-CODE-005 | DES in `com.sun.mail.auth.Ntlm` | Correct, not actionable | The NTLM protocol requires DES; JavaMail library code. |
| 15 | OpenContacts | AG-CODE-001 | `DexFile` in `LV0/c;->a` | Correct, not actionable | Obfuscated AndroidX MultiDex (`secondary-dexes`), standard on old Android versions. |
| 16 | Date-a-base | AG-CODE-002 | `androidx.tracing.Trace`: 9 reflective calls | Correct, not actionable | AndroidX internals, constant names. |
| 17 | LRC Editor | AG-CODE-002 | `Lq/f;`: 13 reflective calls | Correct, not actionable | Obfuscated library code, constant names. |
| 18 | Brick Blast | AG-CODE-002 | `Lv3;` reflects into `ActivityThread` | Correct, not actionable | Common AndroidX-style hidden API access. |
| 19 | Yagni Launcher | AG-PERM-001 | `BIND_ACCESSIBILITY_SERVICE` | Correct, not actionable | A launcher uses accessibility for gestures by design. |
| 20 | SimpleEmail | AG-PERM-002 | Contacts + internet + boot | Correct, not actionable | Exactly what an email client needs. |
| 21 | Presence Publisher | AG-PERM-002 | Background location + internet | Correct, not actionable | Publishing presence is the app's purpose. |
| 22 | BabbyPaint | AG-CODE-004 | Cordova `onReceivedSslError` calls `proceed()` | **FP** | The call only runs when `ApplicationInfo.flags & FLAG_DEBUGGABLE` is set, so never in a release build. The analysis ignores control flow. |
| 23 | BabbyPaint | AG-CODE-004 | Cordova `setAllowUniversalAccessFromFileURLs(true)` | **FP** | Only runs if the `AndroidInsecureFileModeEnabled` preference is set (default false). |

A 24th finding, discovered during the review, was a **rule bug** and has been fixed:

| App | Rule | Finding | Verdict |
|---|---|---|---|
| ReteClock | AG-CODE-007 | `WebAuth.derive` "creates a SecretKeySpec from a hardcoded secret key" | **FP, fixed** |

The key was `password.getBytes("UTF-8")`, where `password` is a method parameter. The constant
tracker treated *any* constant argument of `getBytes` as the source, so it picked up the charset
`"UTF-8"`. It now only looks at the receiver string (or the decoded argument for `Base64.decode`),
with a regression test. The numbers above are from after the fix.

**Summary of the 23 reviewed findings:** 8 true positives (35%), 13 correct but not actionable
(57%), 2 false positives (9%); 3 out of 24 (13%) if the fixed bug is counted.

How to read this:

- **Detection is accurate.** In 21 of 23 cases the code or manifest really contained what the
  finding described. Both remaining false positives come from the same known limitation:
  conditions are ignored (DECISIONS.md #3).
- **Actionability is the weak point.** More than half of the correct findings are in library
  code or describe behaviour that is intended for that kind of app. Library code is the largest
  single cause, which motivated library detection (next section). "By design" findings (a news
  reader for self-hosted servers using HTTP) can only be resolved by the developer, with a
  config suppression.
- **Severity is sometimes too coarse.** An exported provider is always *high*, but in pOT-Droid it
  only serves public images. Severity reflects the pattern, not the data it exposes.
- The sample is small (23) and not uniformly random, so these percentages are rough estimates,
  not a precision measurement.

## Library detection

The review showed that library code is the biggest source of findings that are correct but not
actionable. APKGuard now tags every finding whose class is in a
[known library package](src/apkguard/libraries.py) (AndroidX, Kotlin, `com.google`, OkHttp,
BouncyCastle, ...). By default (`--library-findings separate`) those findings stay in the
reports but are kept out of the summary and the `--fail-on` gate. The evaluation runner uses
`include` mode and records each finding's origin, so both views come from the same scan.

| | All findings | App code only (default) | Change |
|---|---:|---:|---:|
| Findings | 737 | 492 | **−33%** |
| Code findings (`classes*.dex`) | 507 | 271 | −47% |
| AG-CODE-002 reflection | 467 | 250 | −46% |
| High severity | 19 | 14 | −26% |
| Medium severity | 75 | 65 | −13% |
| Apps that fail the default gate (`--fail-on high`) | 12 | 10 | −2 apps |

Most separated findings are AndroidX (195 of 245), followed by `com.google` (9), `kotlinx` (7),
`com.sun` (JavaMail, 7), `kotlin` (6) and `okhttp3` (6). Manifest findings are only separated for
components declared by a library (e.g. `androidx.media.session.MediaButtonReceiver`); permission,
backup and SDK findings always belong to the app.

**Effect on the reviewed sample.** 6 of the 23 reviewed findings are now separated: both false
positives (Cordova's guarded `proceed()` and file-access settings), three correct but
non-actionable findings (BouncyCastle, JavaMail's DES for NTLM, `androidx.tracing`), and **one
true positive**: the `androidx.test` activity that Play NotePad accidentally ships. So the gate
loses both FPs, and the true-positive share among the remaining reviewed findings rises from 35%
to 41% (7 of 17). The lost TP is the price of trusting package names. That's why separated
findings stay visible in JSON/HTML/SARIF instead of being dropped.

**What it cannot do.** It matches package names, so it cannot recognise library code that R8 has
renamed. 253 of the 492 remaining "app" findings are in classes with obfuscated names (every
package and class name ≤ 3 characters, e.g. `La2;`, `Lq/f;`). Almost all of them are reflection
findings, and most are probably renamed AndroidX code. That's why the median app only loses 8% of
its findings: well-separated apps lose a lot, obfuscated apps lose little. Recognising renamed
libraries would need code fingerprinting (as LibScout or LibID do), which is on the roadmap.

**Honesty note.** Five entries in the default list (`com.sun`, `com.getcapacitor`, `org.xbill`,
`io.flutter`, `com.facebook`) were added after looking at this evaluation. They account for 15
of the 245 separated findings; without them the reduction is 31% instead of 33%.

## Baselines across real releases

A baseline is only useful if fingerprints survive a rebuild. To test that on real releases, I
pinned the previous version of each app that F-Droid still hosts (42 of the 50 have one), created
a baseline from the previous release and scanned the current release against it, exactly as CI
would do after an upgrade (`evaluation/run_baseline_eval.py`, results in
[`evaluation/results/baseline_pairs.md`](evaluation/results/baseline_pairs.md)).

| | |
|---|---:|
| Release pairs | 42 |
| Findings in the new releases | 645 |
| Matched the baseline (unchanged) | 483 (75%) |
| Reported as new | 162 (25%) |
| Apps with **no** new findings | 19 of 42 (45%) |
| New findings in obfuscated classes (`La2;`-style names) | 138 of 162 (85%) |
| New findings that are AG-CODE-002 reflection | 144 of 162 |
| Upgrades that would fail the default gate (`--fail-on high`) | **1 of 42** |

I checked all 18 new findings that are not reflection by hand:

- **8 are real changes between the releases**, which is exactly what a baseline should surface:
  new permissions (`REQUEST_INSTALL_PACKAGES` and `CAMERA` in Shelf, `QUERY_ALL_PACKAGES` in
  OpenContacts, `POST_NOTIFICATIONS` in Hauk), newly exported components (`OAuthActivity` and
  `ShareImageActivity` in pOT-Droid, `MIAActionHandler` in OpenContacts) and a changed backup
  configuration (AppStow).
- **10 are renames**: the same code under a new obfuscated name. In pOT-Droid, for example,
  `fragments/h->H2` became `fragments/i->G2`, with the same JavaScript bridge. The one gate failure
  is of this kind: OpenContacts' obfuscated MultiDex class (`LV0/c;`, a dynamic code loading
  finding) was renamed.

So baselines work as intended for manifest and permission findings and for unobfuscated code, but
**R8 renaming is the dominant source of churn**: about 95% of "new" findings were renames, mostly
low-severity reflection findings that do not fail a default build. Projects that obfuscate should
expect to refresh the baseline more often or gate on `high` only. A fix would be to translate
class names back with the R8 `mapping.txt` that the build produces before fingerprinting (on
the roadmap).

## Limitations of this evaluation

- **Benign apps only.** The apps are open-source and reviewed by F-Droid, so this measures noise
  and false positives, not detection rate (recall). Rules for patterns that rarely appear in
  benign apps (hardcoded keys, `debuggable`) are covered by synthetic unit tests instead.
- **Small apps only (≤ 6 MB).** Large apps with many DEX files would take longer; runtime is
  roughly linear in the amount of bytecode.
- **One reviewer, 23 findings.** The verdicts are my judgement after reading the bytecode, not a
  ground-truth dataset.
- **F-Droid builds are often not minified** or only lightly obfuscated, which makes library
  code easier to recognise than in typical Play Store apps.
