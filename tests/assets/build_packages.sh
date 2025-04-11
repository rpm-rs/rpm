#!/bin/sh

# Build packages, using a reproducible configuration (static buildttime, uncompressed payload)
export SOURCE_DATE_EPOCH="1681068559"
REPRODUCIBLE_OPTS=( --define "use_source_date_epoch_as_buildtime 1" --define "%_buildhost localhost" --define "_binary_payload w.ufdio"  --define "_source_payload w.ufdio" )

for spec in SPECS/*.spec; do
    rpmbuild --define "_topdir `pwd`" $"${REPRODUCIBLE_OPTS[@]}" -ba $spec
done

# Cleanup
rm -r ./BUILD/

# Add signatures
RSA_KEY_OPTS=( --define "_gpg_name rpm-signing-key-rsa4096" )
ECDSA_KEY_OPTS=( --define "_gpg_name rpm-signing-key-ecdsa-p256" )
EDDSA_KEY_OPTS=( --define "_gpg_name rpm-signing-key-ed25519" )
IMA_SIGNING_OPTS=( --signfiles --fskpath signing_keys/ima_signing.pem --define "_file_signing_key_password i_am_a_ima_signing_password" )

BASIC_RPM="RPMS/noarch/rpm-basic-2.3.4-5.el9.noarch.rpm"
BASIC_SRPM="SRPMS/rpm-basic-2.3.4-5.el9.src.rpm"

mkdir -p RPMS/signed/

# RSA Signed
RSA_SIGNED_RPM="RPMS/signed/rpm-basic-with-rsa4096-2.3.4-5.el9.noarch.rpm"
cp $BASIC_RPM $RSA_SIGNED_RPM
rpmsign --addsign $RSA_SIGNED_RPM $"${RSA_KEY_OPTS[@]}"

# ECDSA (nist-p256) Signed
ECDSA_SIGNED_RPM="RPMS/signed/rpm-basic-with-ecdsa-2.3.4-5.el9.noarch.rpm"
cp $BASIC_RPM $ECDSA_SIGNED_RPM
rpmsign --addsign $ECDSA_SIGNED_RPM $"${ECDSA_KEY_OPTS[@]}"

# EdDSA Signed
EDDSA_SIGNED_RPM="RPMS/signed/rpm-basic-with-ed25519-2.3.4-5.el9.noarch.rpm"
cp $BASIC_RPM $EDDSA_SIGNED_RPM
rpmsign --addsign $EDDSA_SIGNED_RPM $"${EDDSA_KEY_OPTS[@]}"

# Package signed with all possible signatures (rpm v6 feature) + IMA file signing
# Building this only works with a sufficiently fresh version of RPM, otherwise you get only the latest signature
IMA_SIGNED_RPM="RPMS/signed/rpm-basic-with-ima-2.3.4-5.el9.noarch.rpm"
cp $BASIC_RPM $IMA_SIGNED_RPM
rpmsign --addsign $IMA_SIGNED_RPM $"${EDDSA_KEY_OPTS[@]}"
rpmsign --addsign $IMA_SIGNED_RPM $"${ECDSA_KEY_OPTS[@]}"
rpmsign --addsign $IMA_SIGNED_RPM $"${RSA_KEY_OPTS[@]}" $"${IMA_SIGNING_OPTS[@]}"

# RSA Signed SRPM
RSA_SIGNED_SRPM="SRPMS/signed/rpm-basic-with-rsa4096-2.3.4-5.el9.noarch.rpm"
cp $BASIC_SRPM $RSA_SIGNED_SRPM
rpmsign --addsign $RSA_SIGNED_SRPM $"${RSA_KEY_OPTS[@]}"

# EdDSA Signed SRPM
EDDSA_SIGNED_SRPM="SRPMS/signed/rpm-basic-with-ed25519-2.3.4-5.el9.noarch.rpm"
cp $BASIC_SRPM $EDDSA_SIGNED_SRPM
rpmsign --addsign $EDDSA_SIGNED_SRPM $"${EDDSA_KEY_OPTS[@]}"
