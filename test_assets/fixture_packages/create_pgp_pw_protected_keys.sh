#!/bin/sh

# Generate passphrase-protected rsa4096 PGP keys, in case we need to re-generatate these.

passphrase="thisisN0Tasecuredpassphrase"

gpg --batch --pinentry-mode loopback --passphrase "${passphrase}" \
    --quick-generate-key 'rpm-rs key rsa4096 <rpm-signing-key-protected@example.com>' rsa4096 sign never

gpg --output ./signing_keys/public_rsa4096_protected.asc --armor --export rpm-signing-key-protected@example.com
gpg --batch --pinentry-mode loopback --passphrase "${passphrase}" \
    --output ./signing_keys/secret_rsa4096_protected.asc --armor --export-secret-key rpm-signing-key-protected@example.com
