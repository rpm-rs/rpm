#!/bin/sh

# Remove test keys from the local GPG and Sequoia keyrings that were
# created by generate_keys.sh or imported by import_keys.sh.
# Safe to run multiple times.
#
# Usage: ./clean_keyring.sh [--dry-run]

DRY_RUN=false
if [ "$1" = "--dry-run" ]; then
    DRY_RUN=true
    echo "Dry run mode — no keys will be deleted."
fi

run() {
    echo "  $*"
    if ! $DRY_RUN; then
        "$@"
    fi
}

GPG_V4_EMAILS="
    rpm-testkey-v4-rsa4096@example.com
    rpm-testkey-v4-ed25519@example.com
    rpm-testkey-v4-protected@example.com
    rpm-testkey-v4-ecdsa-nistp256@example.com
"
for email in $GPG_V4_EMAILS; do
    fingerprints=$(gpg --list-secret-keys --with-colons "$email" 2>/dev/null | awk -F: '/^fpr:/{print $10}')
    for fpr in $fingerprints; do
        echo "GPG: deleting key $fpr ($email)"
        run gpg --batch --yes --delete-secret-and-public-key "$fpr" 2>/dev/null || true
    done
done

SQ_CERT_D="${HOME}/.local/share/pgp.cert.d"
SQ_SOFTKEYS="${HOME}/.local/share/sequoia/keystore/softkeys"

# Find all test-related Sequoia certs by grepping for rpm-testkey or
# rpm-signing-key in user IDs (catches all naming patterns across runs).
fingerprints=$(sq cert list --gossip 2>/dev/null \
    | awk '/^ - [0-9A-F]{40,}/ { fpr=$2 }
           /rpm-testkey|rpm-signing-key/ { if (fpr) print fpr; fpr="" }' \
    | sort -u)

for fpr in $fingerprints; do
    echo "Sequoia: deleting key $fpr"
    # Delete secret key material via the keystore API
    run sq key delete --cert "$fpr" 2>/dev/null || true
    # Delete public certificate from cert-d
    lower_fpr=$(echo "$fpr" | tr 'A-F' 'a-f')
    prefix=$(echo "$lower_fpr" | cut -c1-2)
    rest=$(echo "$lower_fpr" | cut -c3-)
    cert_file="${SQ_CERT_D}/${prefix}/${rest}"
    if [ -f "$cert_file" ]; then
        run rm -f "$cert_file"
    fi
    # Delete orphaned softkey file if the API call couldn't find the cert
    softkey_file="${SQ_SOFTKEYS}/${fpr}.pgp"
    if [ -f "$softkey_file" ]; then
        run rm -f "$softkey_file"
    fi
done
