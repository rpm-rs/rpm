use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use rpm::*;

mod common;

#[test]
fn test_package_segment_boundaries() -> Result<(), Box<dyn std::error::Error>> {
    assert_boundaries(common::rpm_389_ds_file_path().as_ref())?;
    assert_boundaries(common::rpm_ima_signed_file_path().as_ref())?;
    assert_boundaries(common::rpm_empty_path().as_ref())?;
    assert_boundaries(common::rpm_empty_source_path().as_ref())?;

    let constructed_pkg =
        rpm::PackageBuilder::new("empty-package", "0", "MIT", "x86_64", "").build()?;
    constructed_pkg.write(&mut File::create("/tmp/empty_pkg.rpm")?)?;
    assert_boundaries(Path::new("/tmp/empty_pkg.rpm"))?;

    #[cfg(feature = "signature-meta")]
    {
        use rpm::signature::pgp::Signer;
        let signing_key = common::rsa_private_key();
        let signer = Signer::load_from_asc_bytes(signing_key.as_ref())?;
        let constructed_pkg_with_sig =
            rpm::PackageBuilder::new("empty-package", "0", "MIT", "x86_64", "")
                .build_and_sign(signer)?;
        constructed_pkg_with_sig.write(&mut File::create("/tmp/empty_pkg_with_sig.rpm")?)?;
        assert_boundaries(Path::new("/tmp/empty_pkg_with_sig.rpm"))?;
    }

    fn assert_boundaries(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let mut f = File::open(path)?;
        let package = rpm::Package::open(path)?;
        let offsets = package.metadata.get_package_segment_offsets();

        // Verify that we see an RPM magic #
        let mut buf = [0u8; 4];
        f.read_exact(&mut buf)?;

        assert_eq!(buf, RPM_MAGIC);

        // Seek to the start of the sig header and verify that we see a header magic #
        f.seek(SeekFrom::Start(offsets.signature_header))?;
        let mut buf = [0u8; 3];
        f.read_exact(&mut buf)?;

        assert_eq!(buf, HEADER_MAGIC);

        // Seek to the start of the header and verify that we see a header magic #
        f.seek(SeekFrom::Start(offsets.header))?;
        let mut buf = [0u8; 3];
        f.read_exact(&mut buf)?;

        assert_eq!(buf, HEADER_MAGIC);

        // Seek to the start of the payload and verify that we see a magic # appropriate for the payload type
        f.seek(SeekFrom::Start(offsets.payload))?;
        let mut buf = [0u8; 10];
        f.read_exact(&mut buf)?;

        let payload_magic: &[u8] = match package.metadata.get_payload_compressor().unwrap() {
            CompressionType::Gzip => &[0x1f, 0x8b],
            CompressionType::Zstd => &[0x28, 0xb5, 0x2f, 0xfd],
            CompressionType::Xz => &[0xfd, 0x37, 0x7a, 0x58, 0x5a],
            CompressionType::Bzip2 => &[0x42, 0x5a],
            CompressionType::None => &[0x30, 0x37, 0x30, 0x37, 0x30, 0x31], // CPIO archive magic #
        };

        assert!(buf.starts_with(payload_magic));

        Ok(())
    }

    Ok(())
}

#[test]
fn test_no_rpm_files() -> Result<(), Box<dyn std::error::Error>> {
    let rpm_file_path = common::rpm_empty_path();
    let package = Package::open(rpm_file_path)?;

    assert!(package.metadata.get_file_paths()?.is_empty());
    assert!(package.metadata.get_file_entries()?.is_empty());

    Ok(())
}
