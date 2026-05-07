"""Extract an RPM's payload to a directory."""

import argparse

from rpm_rs import Package

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("rpm", help="Path to the RPM file")
parser.add_argument("destination", nargs="?", default=".", help="Output directory")
args = parser.parse_args()

dest = args.destination
pkg = Package.open(args.rpm)
nevra = pkg.metadata.nevra()
print(f"Extracting {nevra} to {dest}/")

for f in pkg.files():
    print(f"  {f.metadata.path}")

pkg.extract(dest)
