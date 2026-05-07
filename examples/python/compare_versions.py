"""Compare two NEVRA strings and print which is newer."""

import argparse

from rpm_rs import Nevra

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("nevra1", help="First NEVRA string")
parser.add_argument("nevra2", help="Second NEVRA string")
args = parser.parse_args()

a = Nevra.parse(args.nevra1)
b = Nevra.parse(args.nevra2)

if a < b:
    print(f"{a} < {b}")
elif a == b:
    print(f"{a} == {b}")
else:
    print(f"{a} > {b}")
