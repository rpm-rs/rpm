#!/bin/sh

export SOURCE_DATE_EPOCH="1681068559"
REPRODUCIBLE_OPTS=( --define "use_source_date_epoch_as_buildtime 1" --define "_binary_payload w.ufdio"  --define "_source_payload w.ufdio" )

for spec in SPECS/*.spec; do
    rpmbuild --define "_topdir `pwd`" $"${REPRODUCIBLE_OPTS[@]}" -ba $spec
done

rm -r ./BUILDROOT/
rm -r ./BUILD/

RSA_KEY_OPTS=( --define "_gpg_name rsa3072-rpm-signing-key" )
EDDSA_KEY_OPTS=( --define "_gpg_name ed25519-rpm-signing-key" )

rpmsign --addsign RPMS/x86_64/rpm-empty-0-0.x86_64.rpm $"${EDDSA_KEY_OPTS[@]}"
rpmsign --addsign RPMS/x86_64/rpm-feature-coverage-2.3.4-5.el8.x86_64.rpm $"${RSA_KEY_OPTS[@]}"

# @todo: how to make IMA signing work? I get errors.
# --define "_file_signing_key rsa3072-rpm-signing-key" --signfiles
