#!/bin/sh

passphrase="thisisN0Tasecuredpassphrase"

gpg --import ./signing_keys/v4/rpm-testkey-v4-rsa4096.secret
gpg --batch --passphrase="${passphrase}" --pinentry-mode=loopback --import ./signing_keys/v4/rpm-testkey-v4-rsa3072-protected.secret
gpg --import ./signing_keys/v4/rpm-testkey-v4-ed25519.secret
gpg --import ./signing_keys/v4/rpm-testkey-v4-ecdsa-nistp256.secret

sudo rpm -v --import ./signing_keys/v4/rpm-testkey-v4-rsa4096.asc
sudo rpm -v --import ./signing_keys/v4/rpm-testkey-v4-rsa3072-protected.asc
# this will fail with older versions of RPM, so for the sake of better UX we ignore failures
sudo rpm -v --import ./signing_keys/v4/rpm-testkey-v4-ed25519.asc || true
sudo rpm -v --import ./signing_keys/v4/rpm-testkey-v4-ecdsa-nistp256.asc || true



SQ_V6_KEYS="
    ./signing_keys/v6/rpm-testkey-v6-rsa4k.secret
    ./signing_keys/v6/rpm-testkey-v6-ed25519.secret
    ./signing_keys/v6/rpm-testkey-v6-mldsa65-ed25519.secret
"
for key in $SQ_V6_KEYS; do
    cert="${key%.secret}.asc"
    sq cert import "$cert"
    sq key import "$key"
    # Mark as own key so user IDs are authenticated (required for --signer-userid)
    fpr=$(sq inspect "$key" 2>/dev/null | awk '/Fingerprint:/{print $2; exit}')
    sq pki link authorize --unconstrained --cert="$fpr" --all
done

sudo rpm -v --import ./signing_keys/v6/rpm-testkey-v6-rsa4k.asc || true
sudo rpm -v --import ./signing_keys/v6/rpm-testkey-v6-ed25519.asc || true
sudo rpm -v --import ./signing_keys/v6/rpm-testkey-v6-mldsa65-ed25519.asc || true
