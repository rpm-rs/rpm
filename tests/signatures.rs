use std::path::Path;

use rpm::chrono::TimeZone;
use rpm::signature::pgp::{Signer, Verifier};
use rpm::*;

mod common;

#[test]
fn test_rpm_file_signatures_resign_rsa() -> Result<(), Box<dyn std::error::Error>> {
    let pkg_path = common::rpm_ima_signed_file_path();
    let (signing_key, verification_key) = common::load_rsa_keys();
    resign_and_verify_with_keys(pkg_path.as_ref(), &signing_key, &verification_key)
}

#[test]
fn test_rpm_file_signatures_resign_eddsa() -> Result<(), Box<dyn std::error::Error>> {
    let pkg_path = common::rpm_ima_signed_file_path();
    let (signing_key, verification_key) = common::load_eddsa_keys();
    resign_and_verify_with_keys(pkg_path.as_ref(), &signing_key, &verification_key)
}

#[track_caller]
fn resign_and_verify_with_keys(
    pkg_path: &Path,
    signing_key: &[u8],
    verification_key: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut package = Package::open(pkg_path)?;
    let signer = Signer::load_from_asc_bytes(signing_key)?;
    package.sign_with_timestamp(&signer, 1_600_000_000)?;

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
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = env_logger::try_init();

    let cargo_file = common::cargo_manifest_dir().join("Cargo.toml");

    let mut pkg = PackageBuilder::new(
        "roundtrip",
        "1.0.0",
        "MIT",
        "x86_64",
        "spins round and round",
    )
    .compression(CompressionType::Gzip)
    .with_file(
        cargo_file.to_str().unwrap(),
        FileOptions::new("/etc/foobar/hugo/bazz.toml")
            .mode(FileMode::regular(0o777))
            .is_config(),
    )?
    .with_file(
        cargo_file.to_str().unwrap(),
        FileOptions::new("/etc/Cargo.toml"),
    )?
    .epoch(3)
    .pre_install_script("echo preinst")
    .add_changelog_entry("you", "yada yada", chrono::Utc.timestamp_opt(1, 0).unwrap())
    .requires(Dependency::any("rpm-sign".to_string()))
    .build()?;

    let epoch = pkg.metadata.get_epoch()?;
    assert_eq!(3, epoch);

    // sign
    let signer = Signer::load_from_asc_bytes(signing_key.as_ref())?;
    pkg.sign(signer)?;

    let out_file = common::cargo_out_dir().join("roundtrip.rpm");
    pkg.write_file(&out_file)?;

    // verify
    let package = Package::open(&out_file)?;
    let verifier = Verifier::load_from_asc_bytes(verification_key.as_ref())?;
    package.verify_signature(verifier)?;

    Ok(())
}

#[test]
fn parse_externally_signed_rpm_and_verify_rsa() -> Result<(), Box<dyn std::error::Error>> {
    let _ = env_logger::try_init();
    let (signing_key, verification_key) = common::load_rsa_keys();

    build_parse_sign_and_verify(&signing_key, &verification_key)
}

#[test]
fn parse_externally_signed_rpm_and_verify_eddsa() -> Result<(), Box<dyn std::error::Error>> {
    let _ = env_logger::try_init();
    let (signing_key, verification_key) = common::load_eddsa_keys();

    build_parse_sign_and_verify(&signing_key, &verification_key)
}
