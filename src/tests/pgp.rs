#![cfg(feature = "signature-pgp")]

use super::*;

use crate::signature::pgp::{Signer, Verifier};

#[test]
fn test_rpm_file_signatures_resign() -> Result<(), Box<dyn std::error::Error>> {
    let rpm_file_path = file_signatures_test_rpm_file_path();
    let mut package = RPMPackage::open(rpm_file_path)?;

    let private_key_content = std::fs::read(test_private_key_path())?;
    let signer = Signer::load_from_asc_bytes(&private_key_content)?;

    package.sign(&signer)?;

    let public_key_content = std::fs::read(test_public_key_path())?;
    let verifier = Verifier::load_from_asc_bytes(&public_key_content).unwrap();
    package
        .verify_signature(&verifier)
        .expect("failed to verify signature");
    Ok(())
}
