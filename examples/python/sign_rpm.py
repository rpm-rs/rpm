"""Sign an RPM with a PGP private key."""

import argparse

from rpm_rs import Package, Signer

parser = argparse.ArgumentParser(description="Sign an RPM with a PGP private key")
parser.add_argument("rpm", help="Path to the RPM file")
parser.add_argument(
    "-k", "--key", required=True, help="Path to the private key file (ASCII-armored)"
)
parser.add_argument("-o", "--output", help="Output path (default: overwrite input)")
parser.add_argument("-p", "--passphrase", help="Key passphrase (if protected)")
args = parser.parse_args()

signer = Signer.from_file(args.key)
if args.passphrase:
    signer = signer.with_key_passphrase(args.passphrase)

output = args.output or args.rpm

if output == args.rpm:
    try:
        Package.resign_in_place(args.rpm, signer)
    except RuntimeError:
        pkg = Package.open(args.rpm)
        pkg.sign(signer)
        pkg.write_file(output)
else:
    pkg = Package.open(args.rpm)
    pkg.sign(signer)
    pkg.write_file(output)

print(f"Signed: {output}")
