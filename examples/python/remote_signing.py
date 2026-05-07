"""Demonstrate the remote/split signing workflow.

This example shows how to:
1. Extract header bytes from an RPM
2. Sign them externally (simulated here with a local key)
3. Apply the resulting signature back to the package

In a real deployment, step 2 would happen on a remote signing service
(e.g. an HSM, Sigstore, or a signing server behind an API).
"""

import argparse

from rpm_rs import Package, Signer

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("rpm", help="Path to the RPM file")
parser.add_argument("key", help="Path to the private key file (ASCII-armored)")
parser.add_argument("output", help="Output path for the signed RPM")
args = parser.parse_args()

rpm_path, key_path, output_path = args.rpm, args.key, args.output

pkg = Package.open(rpm_path)

# Step 1: Extract the header bytes that need to be signed.
header_bytes = pkg.header_bytes()
print(f"Extracted {len(header_bytes)} header bytes for signing")

# Step 2: Sign the header bytes.
# In a real workflow, you would send `header_bytes` to a remote service
# and receive `signature_bytes` back. Here we simulate it locally.
signer = Signer.from_file(key_path)
signature_bytes = signer.sign(header_bytes)
print(f"Received {len(signature_bytes)} signature bytes")

# Step 3: Apply the signature to the package.
pkg.apply_signature(signature_bytes)
pkg.write_file(output_path)
print(f"Wrote signed package to {output_path}")
