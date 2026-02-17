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

# If there is no output file specified, we first try to resign in place,
# if the RPM has enough reserved space in the signature header to do so.
# If there's no space or if the user requested a different output file
# then we parse, sign and rewrite the file.
resigned = output == args.rpm
if resigned:
    try:
        Package.resign_in_place(args.rpm, signer)
    except RuntimeError:
        resigned = False

if not resigned:
    pkg = Package.open(args.rpm)
    pkg.sign(signer)
    pkg.write_file(output)

print(f"Signed: {output}")
