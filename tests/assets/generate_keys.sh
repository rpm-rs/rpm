#!/bin/sh

set -e

mkdir -p ./signing_keys/v4 ./signing_keys/v6

# Generate PGP v4 keys

gpg --quick-generate-key --batch --passphrase "" 'rpm-testkey-v4-rsa4096 <rpm-testkey-v4-rsa4096@example.com>' rsa4096 sign never
gpg --quick-generate-key --batch --passphrase "" 'rpm-testkey-v4-ed25519 <rpm-testkey-v4-ed25519@example.com>' ed25519 sign never

passphrase="thisisN0Tasecuredpassphrase"
gpg --quick-generate-key --batch --passphrase "${passphrase}" 'rpm-testkey-v4-rsa3072-protected <rpm-testkey-v4-protected@example.com>' rsa3072 sign never

CONFIG_FILE=$(mktemp /tmp/config.XXXXXX)
trap 'rm -f "$CONFIG_FILE"' EXIT

cat >$CONFIG_FILE <<EOF
    Key-Type: ECDSA
    Key-Usage: sign
    Key-Curve: nistp256
    Name-Real: rpm-testkey-v4-ecdsa-nistp256
    Name-Email: rpm-testkey-v4-ecdsa-nistp256@example.com
    Expire-Date: 0
    %no-ask-passphrase
    %no-protection
EOF
gpg --quiet --batch --expert --full-gen-key $CONFIG_FILE

## Dump PGP v4 keys to file

gpg --output ./signing_keys/v4/rpm-testkey-v4-rsa4096.asc --armor --export rpm-testkey-v4-rsa4096@example.com
gpg --output ./signing_keys/v4/rpm-testkey-v4-rsa4096.secret --armor --export-secret-key rpm-testkey-v4-rsa4096@example.com

gpg --output ./signing_keys/v4/rpm-testkey-v4-ed25519.asc --armor --export rpm-testkey-v4-ed25519@example.com
gpg --output ./signing_keys/v4/rpm-testkey-v4-ed25519.secret --armor --export-secret-key rpm-testkey-v4-ed25519@example.com

gpg --output ./signing_keys/v4/rpm-testkey-v4-ecdsa-nistp256.asc --armor --export rpm-testkey-v4-ecdsa-nistp256@example.com
gpg --output ./signing_keys/v4/rpm-testkey-v4-ecdsa-nistp256.secret --armor --export-secret-key rpm-testkey-v4-ecdsa-nistp256@example.com

gpg --output ./signing_keys/v4/rpm-testkey-v4-rsa3072-protected.asc --armor --export rpm-testkey-v4-protected@example.com
gpg --batch --passphrase="${passphrase}" --pinentry-mode=loopback --output ./signing_keys/v4/rpm-testkey-v4-rsa3072-protected.secret --armor --export-secret-key rpm-testkey-v4-protected@example.com

## Generate PGP v6 keys directly to files

REVDIR=$(mktemp -d)
trap 'rm -rf "$CONFIG_FILE" "$REVDIR"' EXIT

sq key generate \
	--own-key \
	--name "rpm-testkey-v6-rsa4k" \
	--email "rpm-testkey-v6-rsa4k@example.org" \
    --cipher-suite rsa4k \
	--profile rfc9580 \
	--expiration=never \
    --can-sign \
	--cannot-authenticate \
	--cannot-encrypt \
	--without-password \
	--output ./signing_keys/v6/rpm-testkey-v6-rsa4k.secret \
	--rev-cert "$REVDIR/rsa4k.rev"

sq key generate \
	--own-key \
	--name "rpm-testkey-v6-ed25519" \
	--email "rpm-testkey-v6-ed25519@example.org" \
    --cipher-suite cv25519 \
	--profile rfc9580 \
	--expiration=never \
    --can-sign \
	--cannot-authenticate \
	--cannot-encrypt \
	--without-password \
	--output ./signing_keys/v6/rpm-testkey-v6-ed25519.secret \
	--rev-cert "$REVDIR/ed25519.rev"

sq key generate \
    --own-key \
    --name "rpm-testkey-v6-mldsa65-ed25519" \
    --email "rpm-testkey-v6-mldsa65-ed25519@example.org" \
    --cipher-suite mldsa65-ed25519 \
    --profile rfc9580 \
    --expiration=never \
    --can-sign \
    --cannot-authenticate \
    --cannot-encrypt \
	--without-password \
	--output ./signing_keys/v6/rpm-testkey-v6-mldsa65-ed25519.secret \
	--rev-cert "$REVDIR/mldsa65-ed25519.rev"

## Extract public certs from secret key files

sq keyring filter --experimental --to-cert --overwrite \
    ./signing_keys/v6/rpm-testkey-v6-rsa4k.secret \
    --output ./signing_keys/v6/rpm-testkey-v6-rsa4k.asc
sq keyring filter --experimental --to-cert --overwrite \
    ./signing_keys/v6/rpm-testkey-v6-ed25519.secret \
    --output ./signing_keys/v6/rpm-testkey-v6-ed25519.asc
sq keyring filter --experimental --to-cert --overwrite \
    ./signing_keys/v6/rpm-testkey-v6-mldsa65-ed25519.secret \
    --output ./signing_keys/v6/rpm-testkey-v6-mldsa65-ed25519.asc

## Generate keyring files containing multiple certificates (for testing keyring support)
## These must be proper keyrings (multiple certs in a single armored block),
## NOT concatenated individual armored blocks.

gpg --output ./signing_keys/v4/rpm-testkey-v4-keyring.asc --armor --export \
    rpm-testkey-v4-rsa4096@example.com \
    rpm-testkey-v4-protected@example.com \
    rpm-testkey-v4-ed25519@example.com

gpg --output ./signing_keys/v4/rpm-testkey-v4-keyring.secret --armor --export-secret-keys \
    rpm-testkey-v4-rsa4096@example.com \
    rpm-testkey-v4-protected@example.com \
    rpm-testkey-v4-ed25519@example.com

sq keyring merge --overwrite \
    ./signing_keys/v6/rpm-testkey-v6-rsa4k.asc \
    ./signing_keys/v6/rpm-testkey-v6-ed25519.asc \
    ./signing_keys/v6/rpm-testkey-v6-mldsa65-ed25519.asc \
    --output ./signing_keys/v6/rpm-testkey-v6-keyring.asc
sq keyring merge --overwrite \
    ./signing_keys/v6/rpm-testkey-v6-rsa4k.secret \
    ./signing_keys/v6/rpm-testkey-v6-ed25519.secret \
    ./signing_keys/v6/rpm-testkey-v6-mldsa65-ed25519.secret \
    --output ./signing_keys/v6/rpm-testkey-v6-keyring.secret

## Generate IMA file signing key

openssl genrsa -out ./signing_keys/ima_signing.pem -passout pass:i_am_a_ima_signing_key 4096
