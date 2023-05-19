# in case we ever need to regenerate these

# gpg --quick-generate-key 'rpm-rs key rsa4096 <rpm-signing-key-rsa4096@example.com>' rsa4096 sign never
# gpg --quick-generate-key 'rpm-rs key ed25519 <rpm-signing-key-ed25519@example.com>' ed25519 sign never

# gpg --output ./signing_keys/public_rsa4096.asc --armor --export rpm-signing-key-rsa4096@example.com
# gpg --output ./signing_keys/secret_rsa4096.asc --armor --export-secret-key rpm-signing-key-rsa4096@example.com

# gpg --output ./signing_keys/public_ed25519.asc --armor --export rpm-signing-key-ed25519@example.com
# gpg --output ./signing_keys/secret_ed25519.asc --armor --export-secret-key rpm-signing-key-ed25519@example.com

gpg --import ./signing_keys/public_rsa4096.asc
gpg --import ./signing_keys/secret_rsa4096.asc
gpg --import ./signing_keys/public_ed25519.asc
gpg --import ./signing_keys/secret_ed25519.asc

sudo rpm --import ./signing_keys/public_rsa4096.asc
sudo rpm --import ./signing_keys/public_ed25519.asc
