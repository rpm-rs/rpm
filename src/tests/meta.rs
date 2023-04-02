#![cfg(feature = "signature-meta")]

use super::*;

#[test]
fn test_rpm_file_signatures() -> Result<(), Box<dyn std::error::Error>> {
    let rpm_file_path = file_signatures_test_rpm_file_path();
    let package = RPMPackage::open(rpm_file_path)?;
    let metadata = &package.metadata;

    let signatures = metadata.get_file_ima_signatures()?;

    assert_eq!(
        signatures,
        [
            "0302041adfaa0e004630440220162785458f5d81d1393cc72afc642c86167c15891ea39213e28907b1c4e8dc6c02202fa86ad2f5e474d36c59300f736f52cb5ed24abb55759a71ec224184a7035a78",
            "0302041adfaa0e00483046022100bd940093777b75650980afb656507f2729a05c9b1bc9986993106de9f301a172022100b3384f6ba200a5a80647a0f0727c5b8f3ab01f74996a1550db605b44af3d10bf",
            "0302041adfaa0e00473045022068953626d7a5b65aa4b1f1e79a2223f2d3500ddcb3d75a7050477db0480a13e10221008637cefe8c570044e11ff95fa933c1454fd6aa8793bbf3e87edab2a2624df460",
        ],
    );

    Ok(())
}

#[test]
fn test_region_tag() -> Result<(), Box<dyn std::error::Error>> {
    let region_entry = Header::create_region_tag(IndexSignatureTag::HEADER_SIGNATURES, 2, 400);

    let possible_binary = region_entry.data.as_binary();

    assert!(possible_binary.is_some(), "should be binary");

    let data = possible_binary.unwrap();

    let (_, entry) = IndexEntry::<IndexSignatureTag>::parse(data)?;

    assert_eq!(entry.tag, IndexSignatureTag::HEADER_SIGNATURES);
    assert_eq!(
        entry.data.type_as_u32(),
        IndexData::Bin(Vec::new()).type_as_u32()
    );
    assert_eq!(-48, entry.offset);

    Ok(())
}
