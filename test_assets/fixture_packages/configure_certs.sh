# in case we ever need to regenerate these

# gpg --quick-generate-key 'rpm-rs key rsa3072 <rpm-signing-key-rsa3072@example.com>' rsa3072 sign never
# gpg --quick-generate-key 'rpm-rs key ed25519 <rpm-signing-key-ed25519@example.com>' ed25519 sign never

# gpg --output ./signing_keys/public_rsa3072.asc --armor --export-secret-key rpm-signing-key-rsa3072@example.com
# gpg --output ./signing_keys/secret_rsa3072.asc --armor --export-secret-key rpm-signing-key-rsa3072@example.com

# gpg --output ./signing_keys/public_ed25519.asc --armor --export-secret-key rpm-signing-key-ed25519@example.com
# gpg --output ./signing_keys/secret_ed25519.asc --armor --export-secret-key rpm-signing-key-ed25519@example.com

gpg --import ./signing_keys/public_rsa3072.asc
gpg --import ./signing_keys/secret_rsa3072.asc
gpg --import ./signing_keys/public_ed25519.asc
gpg --import ./signing_keys/secret_ed25519.asc

sudo rpm --import ./signing_keys/public_rsa3072.asc
sudo rpm --import ./signing_keys/public_ed25519.asc
