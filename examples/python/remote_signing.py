"""Demonstrate the remote/split signing workflow.

This example shows how to:
1. Extract header bytes from an RPM
2. Sign them externally (simulated here with a local key)
3. Apply the resulting signature back to the package

In a real deployment, step 2 would happen on a remote signing service
(e.g. an HSM, Sigstore, or a signing server behind an API).
"""

import sys

from rpm_rs import Package, Signer

if len(sys.argv) < 4:
    print("Usage: remote_signing.py <rpm-file> <private-key> <output>", file=sys.stderr)
    sys.exit(1)

rpm_path, key_path, output_path = sys.argv[1], sys.argv[2], sys.argv[3]

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
