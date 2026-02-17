"""Recursively scan a directory for RPM files and parse their metadata."""

import sys
import time
from pathlib import Path

from rpm_rs import PackageMetadata

if len(sys.argv) < 2:
    print("Usage: parse_repo.py <directory>", file=sys.stderr)
    sys.exit(1)

repo_dir = Path(sys.argv[1])
total = 0
errors = 0

start = time.monotonic()

for path in repo_dir.rglob("*.rpm"):
    total += 1
    try:
        meta = PackageMetadata.open(str(path))
        print(f'Found package "{meta.name}" at path {path}')
    except Exception as e:
        errors += 1
        print(f"ERROR {path}: {e}", file=sys.stderr)

elapsed = time.monotonic() - start

print(f"\nParsed {total} packages ({errors} errors) in {elapsed:.2f}s")
