#!/bin/bash
set -euo pipefail

# Build packages, using a reproducible configuration (static buildtime, uncompressed payload)
export SOURCE_DATE_EPOCH="1681068559"
VERSION="2.3.4-5.el9"

REPRODUCIBLE_OPTS=(
    --define "use_source_date_epoch_as_buildtime 1"
    --define "%_buildhost localhost"
    --define "_rpmfilename %{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}.rpm"
)

# v4 signing keys (used with plain --addsign)
V4_RSA_KEY_OPTS=( --define "_gpg_name rpm-testkey-v4-rsa4096" )
V4_ECDSA_KEY_OPTS=( --define "_gpg_name rpm-testkey-v4-ecdsa-nistp256" )
V4_EDDSA_KEY_OPTS=( --define "_gpg_name rpm-testkey-v4-ed25519" )
IMA_SIGNING_OPTS=( --signfiles --fskpath signing_keys/ima_signing.pem --define "_file_signing_key_password i_am_a_ima_signing_key" )

# v6 signing keys (used with --rpmv6 --addsign via Sequoia)
# The default __sq_sign_cmd uses --signer which requires a fingerprint. Override
# it to use --signer-userid so that human-readable key names work. The () suffix
# is required to define it as a parametric macro so %{1} and %{2} expand
# correctly when RPM calls it with the file and signature file paths.
SQ=$(command -v sq)
V6_SQ_OPTS=(
    --define "_openpgp_sign sq"
    --define "__sq ${SQ}"
    --define '__sq_sign_cmd() %{shescape:%{__sq}} sign %{?_openpgp_sign_id:--signer-userid %{_openpgp_sign_id}} %{?_sq_sign_cmd_extra_args} --binary --signature-file %{shescape:%{2}} -- %{shescape:%{1}}'
)
V6_RSA_KEY_OPTS=( "${V6_SQ_OPTS[@]}" --define "_gpg_name rpm-testkey-v6-rsa4k" )
V6_EDDSA_KEY_OPTS=( "${V6_SQ_OPTS[@]}" --define "_gpg_name rpm-testkey-v6-ed25519" )
V6_MLDSA_KEY_OPTS=( "${V6_SQ_OPTS[@]}" --define "_gpg_name rpm-testkey-v6-mldsa65-ed25519" )

# Build a single spec file
#   $1 = spec file path
#   $2 = rpm format (4 or 6)
#   $3 = payload compression macro (e.g. "w.ufdio", "w9.gzdio")
#   $4 = (optional) rpmdir override for compression variants
build_spec() {
    local spec=$1
    local fmt=$2
    local payload=$3
    local rpmdir="${4:-$(pwd)/RPMS/v${fmt}}"
    local srpmdir="$(pwd)/SRPMS/v${fmt}"

    mkdir -p "$rpmdir" "$srpmdir"

    local fmt_opts=()
    if [[ "$fmt" == "4" ]]; then
        fmt_opts+=( --define "_use_weak_usergroup_deps 1" )
    fi

    rpmbuild \
        --define "_topdir $(pwd)" \
        --define "_rpmdir ${rpmdir}" \
        --define "_srcrpmdir ${srpmdir}" \
        --define "_rpmformat ${fmt}" \
        --define "_binary_payload ${payload}" \
        --define "_source_payload ${payload}" \
        "${REPRODUCIBLE_OPTS[@]}" \
        "${fmt_opts[@]}" \
        -ba "$spec"

    rm -rf ./BUILD/
}

# Build rpm-basic and rpm-empty for both v4 and v6 (uncompressed),
# plus rpm-basic v6 with all compression types
build_basic_packages() {
    for spec in SPECS/rpm-basic.spec SPECS/rpm-empty.spec; do
        for fmt in 4 6; do
            build_spec "$spec" "$fmt" "w.ufdio"
        done
    done

    # v6: compressed variants (separate subdirectories)
    for payload_name in gzip xz zstd; do
        case "$payload_name" in
            gzip) payload="w9.gzdio" ;;
            xz)   payload="w9.xzdio" ;;
            zstd)  payload="w19.zstdio" ;;
        esac
        build_spec SPECS/rpm-basic.spec 6 "$payload" \
            "$(pwd)/RPMS/v6/${payload_name}"
    done
}

# Build all other specs once (v6, uncompressed)
build_other_packages() {
    for spec in SPECS/*.spec; do
        [[ "$spec" == *rpm-basic* || "$spec" == *rpm-empty* ]] && continue
        build_spec "$spec" 6 "w.ufdio"
    done
}

sign_v4_packages() {
    local rpmdir="RPMS/v4"
    local srpmdir="SRPMS/v4"

    BASIC_RPM="${rpmdir}/rpm-basic-${VERSION}.noarch.rpm"
    BASIC_SRPM="${srpmdir}/rpm-basic-${VERSION}.src.rpm"

    mkdir -p "${rpmdir}/signed" "${srpmdir}/signed"

    # RSA Signed
    RSA_SIGNED_RPM="${rpmdir}/signed/rpm-basic-with-rsa4096-${VERSION}.noarch.rpm"
    cp "$BASIC_RPM" "$RSA_SIGNED_RPM"
    rpmsign --addsign "$RSA_SIGNED_RPM" "${V4_RSA_KEY_OPTS[@]}"

    # No fixture for the passphrase-protected RSA key — the passphrase only
    # affects decrypting the private key, not the resulting signature or its
    # verification. That code path is exercised in the Rust integration tests.

    # ECDSA (nist-p256) Signed
    ECDSA_SIGNED_RPM="${rpmdir}/signed/rpm-basic-with-ecdsa-${VERSION}.noarch.rpm"
    cp "$BASIC_RPM" "$ECDSA_SIGNED_RPM"
    rpmsign --addsign "$ECDSA_SIGNED_RPM" "${V4_ECDSA_KEY_OPTS[@]}"

    # EdDSA Signed
    EDDSA_SIGNED_RPM="${rpmdir}/signed/rpm-basic-with-ed25519-${VERSION}.noarch.rpm"
    cp "$BASIC_RPM" "$EDDSA_SIGNED_RPM"
    rpmsign --addsign "$EDDSA_SIGNED_RPM" "${V4_EDDSA_KEY_OPTS[@]}"

    # Package signed with multiple signatures + IMA file signing
    # Requires a sufficiently fresh version of RPM with --rpmv6 support
    IMA_SIGNED_RPM="${rpmdir}/signed/rpm-basic-with-ima-${VERSION}.noarch.rpm"
    cp "$BASIC_RPM" "$IMA_SIGNED_RPM"
    rpmsign --rpmv6 --addsign "$IMA_SIGNED_RPM" "${V4_EDDSA_KEY_OPTS[@]}"
    rpmsign --rpmv6 --addsign "$IMA_SIGNED_RPM" "${V4_ECDSA_KEY_OPTS[@]}"
    rpmsign --rpmv6 --addsign "$IMA_SIGNED_RPM" "${V4_RSA_KEY_OPTS[@]}" "${IMA_SIGNING_OPTS[@]}"

    # RSA Signed SRPM
    RSA_SIGNED_SRPM="${srpmdir}/signed/rpm-basic-with-rsa4096-${VERSION}.src.rpm"
    cp "$BASIC_SRPM" "$RSA_SIGNED_SRPM"
    rpmsign --addsign "$RSA_SIGNED_SRPM" "${V4_RSA_KEY_OPTS[@]}"

    # EdDSA Signed SRPM
    EDDSA_SIGNED_SRPM="${srpmdir}/signed/rpm-basic-with-ed25517-${VERSION}.src.rpm"
    cp "$BASIC_SRPM" "$EDDSA_SIGNED_SRPM"
    rpmsign --addsign "$EDDSA_SIGNED_SRPM" "${V4_EDDSA_KEY_OPTS[@]}"
}

sign_v6_packages() {
    local rpmdir="RPMS/v6"
    local srpmdir="SRPMS/v6"

    BASIC_RPM="${rpmdir}/rpm-basic-${VERSION}.noarch.rpm"
    BASIC_SRPM="${srpmdir}/rpm-basic-${VERSION}.src.rpm"

    mkdir -p "${rpmdir}/signed" "${srpmdir}/signed"

    # RSA Signed
    RSA_SIGNED_RPM="${rpmdir}/signed/rpm-basic-with-rsa4k-${VERSION}.noarch.rpm"
    cp "$BASIC_RPM" "$RSA_SIGNED_RPM"
    rpmsign --rpmv6 --addsign "$RSA_SIGNED_RPM" "${V6_RSA_KEY_OPTS[@]}"

    # Ed25519 Signed
    EDDSA_SIGNED_RPM="${rpmdir}/signed/rpm-basic-with-ed25519-${VERSION}.noarch.rpm"
    cp "$BASIC_RPM" "$EDDSA_SIGNED_RPM"
    rpmsign --rpmv6 --addsign "$EDDSA_SIGNED_RPM" "${V6_EDDSA_KEY_OPTS[@]}"

    # MLDSA65+Ed25519 Signed
    MLDSA_SIGNED_RPM="${rpmdir}/signed/rpm-basic-with-mldsa65-ed25519-${VERSION}.noarch.rpm"
    cp "$BASIC_RPM" "$MLDSA_SIGNED_RPM"
    rpmsign --rpmv6 --addsign "$MLDSA_SIGNED_RPM" "${V6_MLDSA_KEY_OPTS[@]}"

    # Package with multiple v6 signatures
    MULTI_SIGNED_RPM="${rpmdir}/signed/rpm-basic-multiple-signatures-${VERSION}.noarch.rpm"
    cp "$BASIC_RPM" "$MULTI_SIGNED_RPM"
    rpmsign --rpmv6 --addsign "$MULTI_SIGNED_RPM" "${V6_EDDSA_KEY_OPTS[@]}"
    rpmsign --rpmv6 --addsign "$MULTI_SIGNED_RPM" "${V6_RSA_KEY_OPTS[@]}"

    # RSA Signed SRPM
    RSA_SIGNED_SRPM="${srpmdir}/signed/rpm-basic-with-rsa4k-${VERSION}.src.rpm"
    cp "$BASIC_SRPM" "$RSA_SIGNED_SRPM"
    rpmsign --rpmv6 --addsign "$RSA_SIGNED_SRPM" "${V6_RSA_KEY_OPTS[@]}"

    # Ed25519 Signed SRPM
    EDDSA_SIGNED_SRPM="${srpmdir}/signed/rpm-basic-with-ed25519-${VERSION}.src.rpm"
    cp "$BASIC_SRPM" "$EDDSA_SIGNED_SRPM"
    rpmsign --rpmv6 --addsign "$EDDSA_SIGNED_SRPM" "${V6_EDDSA_KEY_OPTS[@]}"
}

build_basic_packages
build_other_packages
sign_v4_packages
sign_v6_packages
