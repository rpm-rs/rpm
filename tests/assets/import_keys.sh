#!/bin/sh

passphrase="thisisN0Tasecuredpassphrase"

gpg --import ./signing_keys/public_rsa4096.asc
gpg --import ./signing_keys/secret_rsa4096.asc
gpg --import ./signing_keys/public_rsa3072_protected.asc
gpg --batch --passphrase="${passphrase}" --pinentry-mode=loopback --import ./signing_keys/secret_rsa3072_protected.asc
gpg --import ./signing_keys/public_ed25519.asc
gpg --import ./signing_keys/secret_ed25519.asc
gpg --import ./signing_keys/public_ecdsa_nistp256.asc
gpg --import ./signing_keys/secret_ecdsa_nistp256.asc

rpm -v --import ./signing_keys/public_rsa4096.asc
rpm -v --import ./signing_keys/public_rsa3072_protected.asc
# this will fail with older versions of RPM, so for the sake of better UX we ignore failures
rpm -v --import ./signing_keys/public_ed25519.asc || true
rpm -v --import ./signing_keys/public_ecdsa_nistp256.asc || true
