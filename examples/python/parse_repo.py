"""Recursively scan a directory for RPM files and parse their metadata."""

import argparse
import sys
import time
from pathlib import Path

from rpm_rs import PackageMetadata

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("directory", help="Directory to scan for RPM files")
args = parser.parse_args()

repo_dir = Path(args.directory)
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
