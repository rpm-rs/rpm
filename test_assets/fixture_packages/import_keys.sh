gpg --import ./signing_keys/public_rsa4096.asc
gpg --import ./signing_keys/secret_rsa4096.asc
gpg --import ./signing_keys/public_rsa3072_protected.asc
gpg --import ./signing_keys/secret_rsa3072_protected.asc
gpg --import ./signing_keys/public_ed25519.asc
gpg --import ./signing_keys/secret_ed25519.asc
gpg --import ./signing_keys/public_ecdsa_nistp256.asc
gpg --import ./signing_keys/secret_ecdsa_nistp256.asc

sudo rpm -v --import ./signing_keys/public_rsa4096.asc
sudo rpm -v --import ./signing_keys/public_rsa3072_protected.asc
sudo rpm -v --import ./signing_keys/public_ed25519.asc
sudo rpm -v --import ./signing_keys/public_ecdsa_nistp256.asc
