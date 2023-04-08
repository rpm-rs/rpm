## in case we ever need to regenerate these, here's the commands to regenerate them
## but since they're already committed, probably you just want to import them

## Generate the unprotected PGP keys

# gpg --quick-generate-key 'rpm-rs key rsa4096 <rpm-signing-key-rsa4096@example.com>' rsa4096 sign never
# gpg --quick-generate-key 'rpm-rs key ed25519 <rpm-signing-key-ed25519@example.com>' ed25519 sign never

# gpg --output ./signing_keys/public_rsa4096.asc --armor --export rpm-signing-key-rsa4096@example.com
# gpg --output ./signing_keys/secret_rsa4096.asc --armor --export-secret-key rpm-signing-key-rsa4096@example.com

# gpg --output ./signing_keys/public_ed25519.asc --armor --export rpm-signing-key-ed25519@example.com
# gpg --output ./signing_keys/secret_ed25519.asc --armor --export-secret-key rpm-signing-key-ed25519@example.com

## Generate passphrase-protected PGP keys

# passphrase="thisisN0Tasecuredpassphrase"

# gpg --passphrase "${passphrase}" --quick-generate-key 'rpm-rs key rsa4096 <rpm-signing-key-protected@example.com>' rsa4096 sign never

# gpg --output ./signing_keys/public_rsa4096_protected.asc --armor --export rpm-signing-key-protected@example.com
# gpg --passphrase "${passphrase}" --output ./signing_keys/secret_rsa4096_protected.asc --armor --export-secret-key rpm-signing-key-protected@example.com

## Generate IMA file signing key
# openssl genrsa -out ./signing_keys/ima_signing.pem -passout pass:i_am_a_ima_signing_key 4096

## Import the keys
gpg --import ./signing_keys/public_rsa4096.asc
gpg --import ./signing_keys/secret_rsa4096.asc
gpg --import ./signing_keys/public_ed25519.asc
gpg --import ./signing_keys/secret_ed25519.asc

rpm -v --import ./signing_keys/public_rsa4096.asc
rpm -v --import ./signing_keys/public_ed25519.asc

gpg --import ./signing_keys/secret_rsa4096_protected.asc
gpg --import ./signing_keys/public_rsa4096_protected.asc

rpm -v --import ./signing_keys/public_rsa4096_protected.asc



# cat > ~/.rpmmacros << EOF_RPMMACROS
# %_signature gpg
# %_gpg_path /root/.gnupg
# %_gpg_name Package Manager
# %_gpgbin /usr/bin/gpg2
# %__gpg_sign_cmd %{__gpg} \
#     --batch \
#     --verbose \
#     --no-armor \
#     --keyid-format long \
#     --pinentry-mode error \
#     --no-secmem-warning \
#     %{?_gpg_digest_algo:--digest-algo %{_gpg_digest_algo}} \
#     --local-user "%{_gpg_name}" \
#     --sign \
#     --detach-sign \
#     --output %{__signature_filename} \
#     %{__plaintext_filename}
# EOF_RPMMACROS

# cat ~/.rpmmacros

### either

#cat > gpgkeyspec <<EOF
#     %echo Generating a basic OpenPGP key
#     Key-Type: RSA
#     Key-Length: 2048
#     Subkey-Type: RSA
#     Subkey-Length: 2048
#     Name-Real: Package Manager
#     Name-Comment: unprotected
#     Name-Email: pmanager@example.com
#     Expire-Date: 0
#     %no-ask-passphrase
#     %no-protection
#     %commit
#     %echo done
#EOF
#gpg --batch --generate-key gpgkeyspec  2>&1
