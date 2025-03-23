#!/bin/sh

## Generate the unprotected PGP keys

gpg --quick-generate-key --batch --passphrase "" 'rpm-rs key rsa4096 <rpm-signing-key-rsa4096@example.com>' rsa4096 sign never
gpg --quick-generate-key --batch --passphrase "" 'rpm-rs key ed25519 <rpm-signing-key-ed25519@example.com>' ed25519 sign never

passphrase="thisisN0Tasecuredpassphrase"
gpg --quick-generate-key --batch --passphrase "${passphrase}" 'rpm-rs key rsa3072 <rpm-signing-key-protected@example.com>' rsa3072 sign never

CONFIG_FILE=$(mktemp /tmp/config.XXXXXX)

cat >$CONFIG_FILE <<EOF
    Key-Type: ECDSA
    Key-Usage: sign
    Key-Curve: nistp256
    Name-Real: rpm-rs
    Name-Comment: key
    Name-Email: rpm-signing-key-ecdsa-nistp256@example.com
    Expire-Date: 0
    %no-ask-passphrase
    %no-protection
EOF

gpg --quiet --batch --expert --full-gen-key $CONFIG_FILE

# Dump PGP keys to file

gpg --output ./signing_keys/public_rsa4096.asc --armor --export rpm-signing-key-rsa4096@example.com
gpg --output ./signing_keys/secret_rsa4096.asc --armor --export-secret-key rpm-signing-key-rsa4096@example.com

gpg --output ./signing_keys/public_ed25519.asc --armor --export rpm-signing-key-ed25519@example.com
gpg --output ./signing_keys/secret_ed25519.asc --armor --export-secret-key rpm-signing-key-ed25519@example.com

gpg --output ./signing_keys/public_ecdsa_nistp256.asc --armor --export rpm-signing-key-ecdsa-nistp256@example.com
gpg --output ./signing_keys/secret_ecdsa_nistp256.asc --armor --export-secret-key rpm-signing-key-ecdsa-nistp256@example.com

gpg --output ./signing_keys/public_rsa3072_protected.asc --armor --export rpm-signing-key-protected@example.com
gpg --batch --passphrase="${passphrase}" --pinentry-mode=loopback --output ./signing_keys/secret_rsa3072_protected.asc --armor --export-secret-key rpm-signing-key-protected@example.com

# ## Generate IMA file signing key

openssl genrsa -out ./signing_keys/ima_signing.pem -passout pass:i_am_a_ima_signing_key 4096
