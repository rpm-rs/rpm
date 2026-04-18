"""Compare two NEVRA strings and print which is newer."""

import sys

from rpm_rs import Nevra

if len(sys.argv) < 3:
    print("Usage: compare_versions.py <nevra1> <nevra2>", file=sys.stderr)
    sys.exit(1)

a = Nevra.parse(sys.argv[1])
b = Nevra.parse(sys.argv[2])

if a < b:
    print(f"{a} < {b}")
elif a == b:
    print(f"{a} == {b}")
else:
    print(f"{a} > {b}")
