"""Download the evaluation APKs from the official F-Droid repository and verify their hashes.

Usage::

    python evaluation/fetch_apks.py            # download into evaluation/apks/
    python evaluation/fetch_apks.py --dest DIR

The list of apps (package, version code, SHA-256) is pinned in ``evaluation/apks.json``: the 50
current versions plus the previous version of 42 of them (for the baseline evaluation). Only
``https://f-droid.org/repo/`` is ever contacted, and a file whose SHA-256 does not match the
pinned value is deleted, so the evaluation always runs on exactly the same bytes.
Standard library only, so it runs before APKGuard is installed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

FDROID_REPO = "https://f-droid.org/repo/"
HERE = Path(__file__).resolve().parent
MANIFEST = HERE / "apks.json"


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(url: str, target: Path) -> None:
    # Write to a temporary name first so an interrupted download never looks complete.
    partial = target.with_suffix(".part")
    request = urllib.request.Request(url, headers={"User-Agent": "apkguard-evaluation"})
    with urllib.request.urlopen(request, timeout=120) as response, partial.open("wb") as fh:
        while chunk := response.read(1 << 20):
            fh.write(chunk)
    partial.replace(target)


def fetch(entry: dict[str, str], dest: Path) -> bool:
    """Make sure ``entry``'s APK exists in ``dest`` with the pinned hash. Returns success."""
    target = dest / entry["file"]
    if target.is_file() and sha256_of(target) == entry["sha256"]:
        print(f"ok       {entry['file']}")
        return True
    url = FDROID_REPO + entry["file"]
    print(f"download {url}")
    try:
        download(url, target)
    except OSError as exc:
        print(f"ERROR    {entry['file']}: {exc}", file=sys.stderr)
        return False
    actual = sha256_of(target)
    if actual != entry["sha256"]:
        target.unlink()
        print(f"ERROR    {entry['file']}: SHA-256 mismatch, file deleted", file=sys.stderr)
        return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dest", type=Path, default=HERE / "apks", help="download directory")
    args = parser.parse_args()
    args.dest.mkdir(parents=True, exist_ok=True)
    pinned = json.loads(MANIFEST.read_text(encoding="utf-8"))
    entries = pinned["apks"] + pinned.get("previous_versions", [])
    failures = sum(not fetch(entry, args.dest) for entry in entries)
    print(f"{len(entries) - failures}/{len(entries)} APKs present and verified in {args.dest}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
