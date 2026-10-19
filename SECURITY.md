# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ |

## Reporting a vulnerability

Please **do not open a public issue** for security problems in APKGuard itself.

Report them privately through GitHub's
[private vulnerability reporting](https://github.com/YOUR_GITHUB_USER/apkguard/security/advisories/new)
or by email to **redoanulkarim1@gmail.com** with "APKGuard security" in the subject. Please
include the version, a description, and steps or a minimal file that reproduces the issue.

You can expect an acknowledgement within 7 days. Once a fix is available, it will be released
and credited to you (unless you prefer otherwise) in the changelog and a GitHub security
advisory.

## Scope

In scope, for example:

- A crafted APK that makes APKGuard execute code, write files outside the requested report
  paths, or consume unbounded memory or time.
- Injection into reports: HTML, SARIF or JSON output that executes script or breaks out of its
  structure when viewed (all APK-controlled text is meant to be escaped).
- Secrets leaking into reports despite redaction.
- The GitHub Action executing untrusted input as shell code.
- The MCP server reading or modifying files beyond the APK and config paths it was given.

Out of scope:

- Findings APKGuard misses or reports wrongly in *scanned apps*: these are false negatives or
  false positives. Please open a normal issue (there is a *False positive* template).
- Vulnerabilities in apps you scanned: report them to that app's developers.

## Things to know when using APKGuard

- **APKs are untrusted input.** APKGuard parses them statically and never executes their code,
  but parsing still goes through androguard and lxml. Scan unknown APKs in a disposable
  environment (the Docker image runs as an unprivileged user).
- **Report contents are attacker-controlled.** Component names, strings and other evidence in
  reports come from the APK. The HTML report escapes them. When you feed results to an AI
  assistant through the MCP server, the assistant should treat them as data, not
  instructions (prompt injection).
- **Secrets are redacted** in all outputs (first four and last two characters plus the length;
  values of 8 characters or fewer are fully masked), but reports
  still reveal *where* a secret is, so treat reports of private apps as confidential.
