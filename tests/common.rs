use rpm::{RPMBuilder, RPMPackage};

pub fn test_private_key_path() -> std::path::PathBuf {
    cargo_manifest_dir().join("test_assets/secret_key.asc")
}

pub fn test_public_key_path() -> std::path::PathBuf {
    cargo_manifest_dir().join("test_assets/public_key.asc")
}

pub fn rpm_389_ds_file_path() -> std::path::PathBuf {
    cargo_manifest_dir().join("test_assets/389-ds-base-devel-1.3.8.4-15.el7.x86_64.rpm")
}

pub fn rpm_ima_signed_file_path() -> std::path::PathBuf {
    cargo_manifest_dir().join("test_assets/ima_signed.rpm")
}

pub fn rpm_empty_source_path() -> std::path::PathBuf {
    cargo_manifest_dir().join("test_assets/fixture_packages/rpm-empty-0-0.src.rpm")
}

pub fn rpm_empty_path() -> std::path::PathBuf {
    cargo_manifest_dir().join("test_assets/fixture_packages/rpm-empty-0-0.x86_64.rpm")
}

pub fn cargo_manifest_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub fn cargo_out_dir() -> std::path::PathBuf {
    cargo_manifest_dir().join("target")
}

pub fn load_asc_keys() -> (Vec<u8>, Vec<u8>) {
    let signing_key = include_bytes!("../test_assets/secret_key.asc");
    let verification_key = include_bytes!("../test_assets/public_key.asc");
    (signing_key.to_vec(), verification_key.to_vec())
}
