#!/bin/sh

# Generate PGP v4 keys

gpg --quick-generate-key --batch --passphrase "" 'rpm-testkey-v4-rsa4096 <rpm-testkey-v4-rsa4096@example.com>' rsa4096 sign never
gpg --quick-generate-key --batch --passphrase "" 'rpm-testkey-v4-ed25519 <rpm-testkey-v4-ed25519@example.com>' ed25519 sign never

passphrase="thisisN0Tasecuredpassphrase"
gpg --quick-generate-key --batch --passphrase "${passphrase}" 'rpm-testkey-v4-rsa3072-protected <rpm-testkey-v4-protected@example.com>' rsa3072 sign never

CONFIG_FILE=$(mktemp /tmp/config.XXXXXX)

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

# ## Dump PGP v4 keys to file

gpg --output ./signing_keys/v4/rpm-testkey-v4-rsa4096.asc --armor --export rpm-testkey-v4-rsa4096@example.com
gpg --output ./signing_keys/v4/rpm-testkey-v4-rsa4096.secret --armor --export-secret-key rpm-testkey-v4-rsa4096@example.com

gpg --output ./signing_keys/v4/rpm-testkey-v4-ed25519.asc --armor --export rpm-testkey-v4-ed25519@example.com
gpg --output ./signing_keys/v4/rpm-testkey-v4-ed25519.secret --armor --export-secret-key rpm-testkey-v4-ed25519@example.com

gpg --output ./signing_keys/v4/rpm-testkey-v4-ecdsa-nistp256.asc --armor --export rpm-testkey-v4-ecdsa-nistp256@example.com
gpg --output ./signing_keys/v4/rpm-testkey-v4-ecdsa-nistp256.secret --armor --export-secret-key rpm-testkey-v4-ecdsa-nistp256@example.com

gpg --output ./signing_keys/v4/rpm-testkey-v4-rsa3072-protected.asc --armor --export rpm-testkey-v4-protected@example.com
gpg --batch --passphrase="${passphrase}" --pinentry-mode=loopback --output ./signing_keys/v4/rpm-testkey-v4-rsa3072-protected.secret --armor --export-secret-key rpm-testkey-v4-protected@example.com

## Generate PGP v6 keys

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
	--without-password

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
	--without-password

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
	--without-password

## Dump PGP v6 keys to file

sq key export --overwrite --cert-email "rpm-testkey-v6-rsa4k@example.org" --output ./signing_keys/v6/rpm-testkey-v6-rsa4k.secret
sq cert export --overwrite --cert-email "rpm-testkey-v6-rsa4k@example.org" --output ./signing_keys/v6/rpm-testkey-v6-rsa4k.asc

sq key export --overwrite --cert-email "rpm-testkey-v6-ed25519@example.org" --output ./signing_keys/v6/rpm-testkey-v6-ed25519.secret
sq cert export --overwrite --cert-email "rpm-testkey-v6-ed25519@example.org" --output ./signing_keys/v6/rpm-testkey-v6-ed25519.asc

sq key export --overwrite --cert-email "rpm-testkey-v6-mldsa65-ed25519@example.org" --output ./signing_keys/v6/rpm-testkey-v6-mldsa65-ed25519.secret
sq cert export --overwrite --cert-email "rpm-testkey-v6-mldsa65-ed25519@example.org" --output ./signing_keys/v6/rpm-testkey-v6-mldsa65-ed25519.asc

## Generate IMA file signing key

openssl genrsa -out ./signing_keys/ima_signing.pem -passout pass:i_am_a_ima_signing_key 4096
