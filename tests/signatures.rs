use std::fs;
use std::{path::Path, time::SystemTime};

use hex;
use rpm::{
    self,
    signature::pgp::{Signer, Verifier},
};

mod common;

/// Resign an already-signed package with new keys, and verify it with the new keys
#[test]
#[ignore]
fn test_rpm_file_signatures_resign() -> Result<(), Box<dyn std::error::Error>> {
    let pkg_path = common::pkgs::v4::RPM_BASIC_RSA_SIGNED;

    // test RSA
    resign_and_verify_with_keys(
        pkg_path.as_ref(),
        &fs::read(common::keys::v4::RSA_4K_PRIVATE)?,
        None,
        &fs::read(common::keys::v4::RSA_4K_PUBLIC)?,
        "rsa_resigned_pkg.rpm",
    )?;

    // test RSA - with secret key protected by a passphrase
    resign_and_verify_with_keys(
        pkg_path.as_ref(),
        &fs::read(common::keys::v4::RSA_3K_PROTECTED_PRIVATE)?,
        Some(common::keys::v4::RSA_3K_PASSPHRASE.to_string()),
        &fs::read(common::keys::v4::RSA_3K_PROTECTED_PUBLIC)?,
        "rsa_resigned_pkg.rpm",
    )?;

    // test EdDSA
    resign_and_verify_with_keys(
        pkg_path.as_ref(),
        &fs::read(common::keys::v4::ED25519_PRIVATE)?,
        None,
        &fs::read(common::keys::v4::ED25519_PUBLIC)?,
        "eddsa_resigned_pkg.rpm",
    )?;

    // test ECDSA
    resign_and_verify_with_keys(
        pkg_path.as_ref(),
        &fs::read(common::keys::v4::ECDSA_NISTP256_PRIVATE)?,
        None,
        &fs::read(common::keys::v4::ECDSA_NISTP256_PUBLIC)?,
        "ecdsa_resigned_pkg.rpm",
    )
}

/// Test parsing packages that were built and signed by RPM
#[test]
fn parse_externally_signed_rpm_and_verify() -> Result<(), Box<dyn std::error::Error>> {
    let _ = env_logger::try_init();

    // v4 RSA
    let verifier = Verifier::load_from_asc_file(common::keys::v4::RSA_4K_PUBLIC)?;
    let package = rpm::Package::open(common::pkgs::v4::RPM_BASIC_RSA_SIGNED)?;
    package.verify_signature(&verifier)?;

    // v4 ECDSA
    let verifier = Verifier::load_from_asc_file(common::keys::v4::ECDSA_NISTP256_PUBLIC)?;
    let package = rpm::Package::open(common::pkgs::v4::RPM_BASIC_ECDSA_SIGNED)?;
    package.verify_signature(&verifier)?;

    // v4 EdDSA
    let verifier = Verifier::load_from_asc_file(common::keys::v4::ED25519_PUBLIC)?;
    let package = rpm::Package::open(common::pkgs::v4::RPM_BASIC_EDDSA_SIGNED)?;
    package.verify_signature(&verifier)?;

    // v6 RSA
    let verifier = Verifier::load_from_asc_file(common::keys::v6::RSA4K_PUBLIC)?;
    let package = rpm::Package::open(common::pkgs::v6::RPM_BASIC_RSA_SIGNED)?;
    package.verify_signature(&verifier)?;

    // v6 EdDSA
    let verifier = Verifier::load_from_asc_file(common::keys::v6::ED25519_PUBLIC)?;
    let package = rpm::Package::open(common::pkgs::v6::RPM_BASIC_EDDSA_SIGNED)?;
    package.verify_signature(&verifier)?;

    // v6 ML-DSA
    let verifier = Verifier::load_from_asc_file(common::keys::v6::MLDSA65_ED25519_PUBLIC)?;
    let package = rpm::Package::open(common::pkgs::v6::RPM_BASIC_MLDSA_SIGNED)?;
    package.verify_signature(&verifier)?;

    // v6 multiple signatures (EdDSA + RSA)
    let package = rpm::Package::open(common::pkgs::v6::RPM_BASIC_MULTI_SIGNED)?;
    let verifier = Verifier::load_from_asc_file(common::keys::v6::ED25519_PUBLIC)?;
    package.verify_signature(&verifier)?;
    let verifier = Verifier::load_from_asc_file(common::keys::v6::RSA4K_PUBLIC)?;
    package.verify_signature(&verifier)?;

    Ok(())
}

/// Test verifying the signature of a package that has been signed by rpm-rs
#[test]
fn parse_signed_rpm_and_verify() -> Result<(), Box<dyn std::error::Error>> {
    let _ = env_logger::try_init();

    // RSA
    build_parse_sign_and_verify(
        &fs::read(common::keys::v4::RSA_4K_PRIVATE)?,
        &fs::read(common::keys::v4::RSA_4K_PUBLIC)?,
        "rsa_signed_pkg.rpm",
    )?;

    // EdDSA
    build_parse_sign_and_verify(
        &fs::read(common::keys::v4::ED25519_PRIVATE)?,
        &fs::read(common::keys::v4::ED25519_PUBLIC)?,
        "eddsa_signed_pkg.rpm",
    )?;

    // ECDSA
    build_parse_sign_and_verify(
        &fs::read(common::keys::v4::ECDSA_NISTP256_PRIVATE)?,
        &fs::read(common::keys::v4::ECDSA_NISTP256_PUBLIC)?,
        "ecdsa_signed_pkg.rpm",
    )?;

    // ML-DSA
    build_parse_sign_and_verify(
        &fs::read(common::keys::v6::MLDSA65_ED25519_PRIVATE)?,
        &fs::read(common::keys::v6::MLDSA65_ED25519_PUBLIC)?,
        "mldsa_signed_pkg.rpm",
    )?;

    Ok(())
}

/// Test an attempt to verify the signature of a package that is not signed
#[test]
#[ignore]
fn test_verify_unsigned_package() -> Result<(), Box<dyn std::error::Error>> {
    let pkg = rpm::Package::open(common::pkgs::v4::RPM_EMPTY)?;

    // test RSA
    let verifier = Verifier::load_from_asc_file(common::keys::v4::RSA_4K_PUBLIC)?;
    assert!(matches!(
        pkg.verify_signature(verifier),
        Err(rpm::Error::NoSignatureFound)
    ));

    // test EdDSA
    let verifier = Verifier::load_from_asc_file(common::keys::v4::ED25519_PUBLIC)?;
    assert!(matches!(
        pkg.verify_signature(verifier),
        Err(rpm::Error::NoSignatureFound)
    ));

    // test ECDSA
    let verifier = Verifier::load_from_asc_file(common::keys::v4::ECDSA_NISTP256_PUBLIC)?;
    assert!(matches!(
        pkg.verify_signature(verifier),
        Err(rpm::Error::NoSignatureFound)
    ));

    Ok(())
}

/// Test an attempt to verify the signature of a package that is not signed
#[test]
fn test_clear_package_signatures() -> Result<(), Box<dyn std::error::Error>> {
    fn sign_clear_and_verify(signing_key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let unsigned_pkg = rpm::PackageBuilder::new(
            "roundtrip",
            "1.0.0",
            "MIT",
            "x86_64",
            "spins round and round",
        )
        .build()?;

        let cleared_pkg = {
            let mut pkg = unsigned_pkg.clone();
            let signer: Signer = Signer::load_from_asc_bytes(signing_key)?;
            pkg.sign(signer)?;
            pkg.clear_signatures()?;
            pkg
        };

        cleared_pkg.verify_digests()?;
        assert_eq!(
            cleared_pkg.metadata.signature,
            unsigned_pkg.metadata.signature
        );

        Ok(())
    }

    sign_clear_and_verify(&fs::read(common::keys::v4::ED25519_PRIVATE)?)?;
    sign_clear_and_verify(&fs::read(common::keys::v4::ECDSA_NISTP256_PRIVATE)?)?;
    sign_clear_and_verify(&fs::read(common::keys::v4::RSA_4K_PRIVATE)?)?;

    Ok(())
}

/// Test an attempt to verify the signature of a package using the wrong key type
#[test]
fn test_verify_package_with_wrong_key_type() -> Result<(), Box<dyn std::error::Error>> {
    let rsa_signer = Signer::load_from_asc_file(common::keys::v4::RSA_4K_PRIVATE)?;
    let rsa_verifier = Verifier::load_from_asc_file(common::keys::v4::RSA_4K_PUBLIC)?;
    let rsa_pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "an empty package")
        .build_and_sign(&rsa_signer)?;

    let eddsa_signer = Signer::load_from_asc_file(common::keys::v4::ED25519_PRIVATE)?;
    let eddsa_verifier = Verifier::load_from_asc_file(common::keys::v4::ED25519_PUBLIC)?;
    let eddsa_pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "an empty package")
        .build_and_sign(&eddsa_signer)?;

    // test EdDSA key with RSA-signed package
    assert!(matches!(
        rsa_pkg.verify_signature(&eddsa_verifier),
        Err(rpm::Error::KeyNotFoundError { key_ref: _ })
    ));

    // test RSA key with EdDSA-signed package
    assert!(matches!(
        eddsa_pkg.verify_signature(&rsa_verifier),
        Err(rpm::Error::KeyNotFoundError { key_ref: _ })
    ));

    Ok(())
}

#[track_caller]
fn resign_and_verify_with_keys(
    pkg_path: &Path,
    signing_key: &[u8],
    signing_key_passphrase: Option<String>,
    verification_key: &[u8],
    pkg_out_path: impl AsRef<Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut package = rpm::Package::open(pkg_path)?;
    let original_header_and_payload_size = package
        .metadata
        .signature
        .get_entry_data_as_u32(rpm::IndexSignatureTag::RPMSIGTAG_SIZE)?;
    let mut signer = Signer::load_from_asc_bytes(signing_key)?;
    if let Some(passphrase) = signing_key_passphrase {
        signer = signer.with_key_passphrase(passphrase);
    }
    package.sign_with_timestamp(&signer, 1_600_000_000)?;

    let out_file = Path::new(common::CARGO_OUT_DIR).join(pkg_out_path.as_ref());
    package.write_file(&out_file)?;

    let package = rpm::Package::open(&out_file)?;

    let new_header_and_payload_size = package
        .metadata
        .signature
        .get_entry_data_as_u32(rpm::IndexSignatureTag::RPMSIGTAG_SIZE)?;

    // Resigning the package should not change the size.
    //
    // Note that this size does not include the signature header, so is unaffected by changes in
    // the signature value.
    assert_eq!(
        original_header_and_payload_size,
        new_header_and_payload_size
    );

    let verifier = Verifier::load_from_asc_bytes(verification_key).unwrap();
    package
        .verify_signature(&verifier)
        .expect("failed to verify signature");
    Ok(())
}

#[track_caller]
fn build_parse_sign_and_verify(
    signing_key: &[u8],
    verification_key: &[u8],
    pkg_out_path: impl AsRef<Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = env_logger::try_init();

    let cargo_file = Path::new(common::CARGO_MANIFEST_DIR).join("Cargo.toml");
    let config = rpm::BuildConfig::default().compression(rpm::CompressionType::Gzip);

    let mut pkg = rpm::PackageBuilder::new(
        "roundtrip",
        "1.0.0",
        "MIT",
        "x86_64",
        "spins round and round",
    )
    .using_config(config)
    .with_file(
        cargo_file.to_str().unwrap(),
        rpm::FileOptions::new("/etc/foobar/hugo/bazz.toml")
            .permissions(0o777)
            .config(),
    )?
    .with_file(
        cargo_file.to_str().unwrap(),
        rpm::FileOptions::new("/etc/Cargo.toml"),
    )?
    .epoch(3)
    .pre_install_script("echo preinst")
    .add_changelog_entry("you", "yada yada", SystemTime::now())
    .requires(rpm::Dependency::any("rpm-sign".to_string()))
    .build()?;

    assert_eq!(3, pkg.metadata.get_epoch()?);

    // sign
    let signer: Signer = Signer::load_from_asc_bytes(signing_key)?;
    pkg.sign(signer)?;

    let out_file = Path::new(common::CARGO_OUT_DIR).join(pkg_out_path.as_ref());
    pkg.write_file(&out_file)?;

    // verify
    let package = rpm::Package::open(&out_file)?;
    let verifier = Verifier::load_from_asc_bytes(verification_key)?;
    package.verify_signature(verifier)?;

    Ok(())
}

mod keyring {
    use super::*;

    /// Sign with a key from the keyring signer and verify with the keyring verifier.
    #[test]
    fn test_sign_with_keyring_signer() -> Result<(), Box<dyn std::error::Error>> {
        // Load a keyring signer — it defaults to the first key in the keyring
        let keyring_signer =
            Signer::load_from_asc_bytes(&fs::read(common::keys::v4::KEYRING_PRIVATE)?)?;
        let pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "keyring signer test")
            .build_and_sign(&keyring_signer)?;

        // Verify with the full keyring — the matching key should be found automatically
        let keyring_verifier = Verifier::load_from_asc_file(common::keys::v4::KEYRING_PUBLIC)?;
        pkg.verify_signature(&keyring_verifier)?;

        Ok(())
    }

    /// Sign with an individual key and verify using a keyring that contains that key
    /// (among others). The verifier should find the matching key automatically.
    #[test]
    fn test_verify_with_keyring() -> Result<(), Box<dyn std::error::Error>> {
        let _ = env_logger::try_init();
        let keyring_verifier = Verifier::load_from_asc_file(common::keys::v4::KEYRING_PUBLIC)?;

        // Sign with RSA key, verify with keyring containing RSA + RSA-protected + Ed25519
        let rsa_signer = Signer::load_from_asc_file(common::keys::v4::RSA_4K_PRIVATE)?;
        let rsa_pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "keyring test")
            .build_and_sign(&rsa_signer)?;
        rsa_pkg.verify_signature(&keyring_verifier)?;

        // Sign with Ed25519 key, verify with the same keyring
        let ed_signer = Signer::load_from_asc_file(common::keys::v4::ED25519_PRIVATE)?;
        let ed_pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "keyring test")
            .build_and_sign(&ed_signer)?;
        ed_pkg.verify_signature(&keyring_verifier)?;

        Ok(())
    }

    /// Verify that a keyring verifier fails when the signing key is NOT in the keyring.
    #[test]
    fn test_verify_with_keyring_wrong_key() -> Result<(), Box<dyn std::error::Error>> {
        // The v4 keyring contains RSA-4K, RSA-3K-protected, and Ed25519 — but NOT ECDSA
        let keyring_verifier = Verifier::load_from_asc_file(common::keys::v4::KEYRING_PUBLIC)?;

        let ecdsa_signer = Signer::load_from_asc_file(common::keys::v4::ECDSA_NISTP256_PRIVATE)?;
        let pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "keyring test")
            .build_and_sign(&ecdsa_signer)?;

        assert!(
            pkg.verify_signature(&keyring_verifier).is_err(),
            "verification should fail when signing key is not in the keyring"
        );

        Ok(())
    }

    /// Use `Verifier::with_key` to select a specific certificate from a keyring
    /// and verify a package signed with that certificate's key.
    #[test]
    fn test_verify_with_key_selection() -> Result<(), Box<dyn std::error::Error>> {
        // Sign a package with the RSA key
        let rsa_signer = Signer::load_from_asc_file(common::keys::v4::RSA_4K_PRIVATE)?;
        let pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "with_key test")
            .build_and_sign(&rsa_signer)?;

        // Get the signer's fingerprint from the package signature
        let fingerprints = pkg.signature_fingerprints()?;
        assert_eq!(fingerprints.len(), 1);
        let signer_fpr_bytes = hex::decode(&fingerprints[0])?;

        // Load the full keyring, then narrow to the matching key
        let keyring_verifier = Verifier::load_from_asc_file(common::keys::v4::KEYRING_PUBLIC)?;
        let filtered_verifier = keyring_verifier.with_key(&signer_fpr_bytes)?;
        pkg.verify_signature(&filtered_verifier)?;

        Ok(())
    }

    /// `Verifier::with_key` should fail when the requested fingerprint is not in the keyring.
    #[test]
    fn test_verify_with_key_not_found() -> Result<(), Box<dyn std::error::Error>> {
        let keyring_verifier = Verifier::load_from_asc_file(common::keys::v4::KEYRING_PUBLIC)?;
        let bogus_fingerprint = [0xDE, 0xAD, 0xBE, 0xEF];
        assert!(matches!(
            keyring_verifier.with_key(&bogus_fingerprint),
            Err(rpm::Error::KeyNotFoundError { key_ref: _ })
        ));
        Ok(())
    }

    /// `Verifier::with_key` should fail verification when the selected key does not
    /// match the key that signed the package, even though the keyring contains the
    /// correct key.
    #[test]
    fn test_verify_with_key_selects_wrong_cert() -> Result<(), Box<dyn std::error::Error>> {
        // Sign with Ed25519, but filter the keyring to only the RSA key
        let ed_signer = Signer::load_from_asc_file(common::keys::v4::ED25519_PRIVATE)?;
        let pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "with_key test")
            .build_and_sign(&ed_signer)?;

        // Get the RSA key's fingerprint from a package signed with it
        let rsa_signer = Signer::load_from_asc_file(common::keys::v4::RSA_4K_PRIVATE)?;
        let rsa_pkg = rpm::PackageBuilder::new("bar", "1.0.0", "MIT", "x86_64", "helper")
            .build_and_sign(&rsa_signer)?;
        let rsa_fingerprints = rsa_pkg.signature_fingerprints()?;
        let rsa_fpr_bytes = hex::decode(&rsa_fingerprints[0])?;

        // Filter keyring to only the RSA cert, then try to verify the Ed25519-signed package
        let keyring_verifier = Verifier::load_from_asc_file(common::keys::v4::KEYRING_PUBLIC)?;
        let rsa_only_verifier = keyring_verifier.with_key(&rsa_fpr_bytes)?;
        assert!(
            pkg.verify_signature(&rsa_only_verifier).is_err(),
            "verification should fail when with_key selects a cert that didn't sign the package"
        );

        Ok(())
    }

    /// Verify that `with_key` selecting by primary key fingerprint works when the
    /// signature was actually made by a subkey of that certificate. This is the
    /// typical v6 case where the primary key is certification-only and a subkey
    /// is used for signing.
    #[test]
    fn test_verify_with_key_matches_primary_when_subkey_signs()
    -> Result<(), Box<dyn std::error::Error>> {
        // v6 Ed25519: primary key is certification-only, subkey has signing flag.
        // The signer auto-selects the signing subkey.
        let signer = Signer::load_from_asc_file(common::keys::v6::ED25519_PRIVATE)?;
        let pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "subkey test")
            .build_and_sign(&signer)?;

        // The signature's issuer fingerprint is the subkey, not the primary key
        let sig_fingerprints = pkg.signature_fingerprints()?;
        assert_eq!(sig_fingerprints.len(), 1);
        let subkey_fpr = &sig_fingerprints[0];

        // Load the public key and get the primary key fingerprint
        let verifier = Verifier::load_from_asc_file(common::keys::v6::ED25519_PUBLIC)?;

        // Get the primary key fingerprint by parsing the public cert directly
        let primary_fpr = {
            use pgp::composed::{Deserializable, SignedPublicKey};
            use pgp::types::KeyDetails;
            let (key, _) = SignedPublicKey::from_armor_file(common::keys::v6::ED25519_PUBLIC)?;
            hex::encode(key.fingerprint().as_bytes())
        };

        // Confirm the primary key fingerprint differs from the signing subkey fingerprint
        assert_ne!(
            primary_fpr, *subkey_fpr,
            "primary and subkey fingerprints should differ for v6 keys"
        );

        // with_key filters by primary fingerprint, but verification should still succeed
        // because the subkey belongs to that certificate
        let filtered_verifier = verifier.with_key(&hex::decode(&primary_fpr)?)?;
        pkg.verify_signature(&filtered_verifier)?;

        Ok(())
    }
}

// @todo:
//  * check for the existence of certain digests
//  * check for the existence of RSA / DSA tags when a key of the appropriate type was used
