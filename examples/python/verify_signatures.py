"""Verify the signatures and digests of an RPM package."""

import argparse
import sys

from rpm_rs import Package, Verifier

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("rpm", help="Path to the RPM file")
parser.add_argument(
    "-k",
    "--key",
    action="append",
    default=[],
    help="Path to a public key file (ASCII-armored)",
)
args = parser.parse_args()

pkg = Package.open(args.rpm)

verifier = Verifier()
for key_file in args.key:
    verifier.load_from_asc_file(key_file)
has_key = bool(args.key)

report = pkg.check_signatures(verifier)
digests = report.digests

print("Digest verification:")
print(f"  Header SHA1      : {digests.header_sha1}")
print(f"  Header SHA256    : {digests.header_sha256}")
print(f"  Header SHA3-256  : {digests.header_sha3_256}")
print(f"  Payload SHA256   : {digests.payload_sha256}")
print(f"  Payload SHA512   : {digests.payload_sha512}")
print(f"  Payload SHA3-256 : {digests.payload_sha3_256}")

if not report.signatures:
    print("\nNo signatures found.")
else:
    print("\nSignatures:")
    for sig in report.signatures:
        info = sig.info
        algo = info.algorithm or "unknown"
        hash_algo = info.hash_algorithm or "unknown"
        fp = f" [{info.fingerprint}]" if info.fingerprint else ""
        status = "OK" if sig.is_verified() else f"FAILED: {sig.error}"
        print(f"  {algo} / {hash_algo}{fp} — {status}")

ok = report.is_ok() if has_key else digests.is_ok()
if ok:
    print("\nResult: OK")
else:
    print("\nResult: FAILED")
    sys.exit(1)
