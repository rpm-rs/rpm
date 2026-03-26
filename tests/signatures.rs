use std::fs;
use std::{path::Path, time::SystemTime};

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

// @todo: we could really just use a fixture for this, better than rebuilding?
/// Test verifying the signature of a package that has been signed
#[test]
fn parse_externally_signed_rpm_and_verify() -> Result<(), Box<dyn std::error::Error>> {
    let _ = env_logger::try_init();

    // test RSA
    build_parse_sign_and_verify(
        &fs::read(common::keys::v4::RSA_4K_PRIVATE)?,
        &fs::read(common::keys::v4::RSA_4K_PUBLIC)?,
        "rsa_signed_pkg.rpm",
    )?;

    // test EdDSA
    build_parse_sign_and_verify(
        &fs::read(common::keys::v4::ED25519_PRIVATE)?,
        &fs::read(common::keys::v4::ED25519_PUBLIC)?,
        "eddsa_signed_pkg.rpm",
    )?;

    // test ECDSA
    build_parse_sign_and_verify(
        &fs::read(common::keys::v4::ECDSA_NISTP256_PRIVATE)?,
        &fs::read(common::keys::v4::ECDSA_NISTP256_PUBLIC)?,
        "ecdsa_signed_pkg.rpm",
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
            .mode(rpm::FileMode::regular(0o777))
            .is_config(),
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

// @todo:
//  * check for the existence of certain digests
//  * check for the existence of RSA / DSA tags when a key of the appropriate type was used
