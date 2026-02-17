"""Extract an RPM's payload to a directory."""

import sys

from rpm_rs import Package

if len(sys.argv) < 2:
    print("Usage: extract_rpm.py <rpm-file> [destination]", file=sys.stderr)
    sys.exit(1)

dest = sys.argv[2] if len(sys.argv) > 2 else "."

pkg = Package.open(sys.argv[1])
nevra = pkg.metadata.nevra()
print(f"Extracting {nevra} to {dest}/")

for f in pkg.files():
    print(f"  {f.metadata.path}")

pkg.extract(dest)
