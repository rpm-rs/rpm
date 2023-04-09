#[allow(dead_code)]
pub fn rpm_389_ds_file_path() -> std::path::PathBuf {
    cargo_manifest_dir().join("test_assets/389-ds-base-devel-1.3.8.4-15.el7.x86_64.rpm")
}

#[allow(dead_code)]
pub fn rpm_ima_signed_file_path() -> std::path::PathBuf {
    cargo_manifest_dir().join("test_assets/ima_signed.rpm")
}

#[allow(dead_code)]
pub fn rpm_empty_source_path() -> std::path::PathBuf {
    cargo_manifest_dir().join("test_assets/fixture_packages/rpm-empty-0-0.src.rpm")
}

#[allow(dead_code)]
pub fn rpm_empty_path() -> std::path::PathBuf {
    cargo_manifest_dir().join("test_assets/fixture_packages/rpm-empty-0-0.x86_64.rpm")
}

#[allow(dead_code)]
pub fn rpm_feature_coverage_pkg_path() -> std::path::PathBuf {
    cargo_manifest_dir()
        .join("test_assets/fixture_packages/rpm-feature-coverage-2.3.4-5.el8.x86_64.rpm")
}

#[allow(dead_code)]
pub fn cargo_manifest_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[allow(dead_code)]
pub fn cargo_out_dir() -> std::path::PathBuf {
    cargo_manifest_dir().join("target")
}

#[allow(dead_code)]
pub fn load_asc_keys() -> (Vec<u8>, Vec<u8>) {
    let signing_key_path = cargo_manifest_dir().join("test_assets/secret_key.asc");
    let signing_key = std::fs::read(signing_key_path).unwrap();

    let verification_key_path = cargo_manifest_dir().join("test_assets/public_key.asc");
    let verification_key = std::fs::read(verification_key_path).unwrap();

    (signing_key.to_vec(), verification_key.to_vec())
}
