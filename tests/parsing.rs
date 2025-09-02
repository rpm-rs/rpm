use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use rpm::*;

mod common;

#[test]
fn test_package_segment_boundaries() -> Result<(), Box<dyn std::error::Error>> {
    assert_boundaries(common::rpm_389_ds_file_path().as_ref())?;
    assert_boundaries(common::rpm_ima_signed_file_path().as_ref())?;
    assert_boundaries(common::rpm_empty_path().as_ref())?;
    assert_boundaries(common::rpm_empty_source_path().as_ref())?;

    let mut temp = tempfile::NamedTempFile::new()?;

    let constructed_pkg =
        rpm::PackageBuilder::new("empty-package", "0", "MIT", "x86_64", "").build()?;
    constructed_pkg.write(&mut temp)?;
    temp.flush()?;
    assert_boundaries(temp.path())?;
    temp.close()?;

    #[cfg(feature = "signature-meta")]
    {
        use rpm::signature::pgp::Signer;
        let signing_key = common::rsa_private_key();
        let signer = Signer::load_from_asc_bytes(signing_key.as_ref())?;
        let constructed_pkg_with_sig =
            rpm::PackageBuilder::new("empty-package", "0", "MIT", "x86_64", "")
                .build_and_sign(signer)?;

        let mut temp = tempfile::NamedTempFile::new()?;

        constructed_pkg_with_sig.write(&mut temp)?;
        temp.flush()?;
        assert_boundaries(temp.path())?;
        temp.close()?;
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
fn test_rpm_file_signatures() -> Result<(), Box<dyn std::error::Error>> {
    let rpm_file_path = common::rpm_ima_signed_file_path();
    let metadata = rpm::PackageMetadata::open(rpm_file_path)?;

    let signatures: Vec<_> = metadata
        .get_file_entries()?
        .iter()
        .map(|f| f.ima_signature.clone())
        .collect();

    assert_eq!(
        signatures,
        [
            Some(String::from(
                "0302041adfaa0e004630440220162785458f5d81d1393cc72afc642c86167c15891ea39213e28907b1c4e8dc6c02202fa86ad2f5e474d36c59300f736f52cb5ed24abb55759a71ec224184a7035a78"
            )),
            Some(String::from(
                "0302041adfaa0e00483046022100bd940093777b75650980afb656507f2729a05c9b1bc9986993106de9f301a172022100b3384f6ba200a5a80647a0f0727c5b8f3ab01f74996a1550db605b44af3d10bf"
            )),
            Some(String::from(
                "0302041adfaa0e00473045022068953626d7a5b65aa4b1f1e79a2223f2d3500ddcb3d75a7050477db0480a13e10221008637cefe8c570044e11ff95fa933c1454fd6aa8793bbf3e87edab2a2624df460"
            )),
        ],
    );

    Ok(())
}
