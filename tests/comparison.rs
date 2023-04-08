use bstr::ByteSlice;
use pretty_assertions;
use rpm::*;

mod common;

/// Compare an empty package built by rpmbuild to an empty package built by rpm-rs
#[test]
fn test_empty_package_equivalent() -> Result<(), Box<dyn std::error::Error>> {
    let mut empty_rpm = RPMPackage::open(common::rpm_empty_path())?;
    let mut built_empty_rpm = RPMBuilder::new("rpm-empty", "0", "LGPL", "x86-64", "").build()?;

    // @TODO: currently failing due to missing tags, different checksums, offsets etc.
    // empty_rpm.canonicalize()?;
    // built_empty_rpm.canonicalize()?;
    // pretty_assertions::assert_eq!(empty_rpm.metadata, built_empty_rpm.metadata);

    // Test that the payload generated is equivalent
    pretty_assertions::assert_str_eq!(
        format!("{:?}", &empty_rpm.content.as_bstr()),
        format!("{:?}", &built_empty_rpm.content.as_bstr()),
    );

    Ok(())
}

/// Compare an empty source package (srpm) built by rpmbuild to an empty source package built by rpm-rs
/// Blocked on completion of source package support
#[ignore = "https://github.com/rpm-rs/rpm/issues/66"]
#[test]
fn test_empty_source_package_equivalent() -> Result<(), Box<dyn std::error::Error>> {
    let mut empty_rpm = RPMPackage::open(common::rpm_empty_source_path())?;
    let mut built_empty_rpm = RPMBuilder::new("rpm-empty", "0", "LGPL", "x86-64", "").build()?;

    // @TODO: currently failing due to missing tags, different checksums, offsets etc.
    // empty_rpm.canonicalize()?;
    // built_empty_rpm.canonicalize()?;
    // pretty_assertions::assert_eq!(empty_rpm.metadata, built_empty_rpm.metadata);

    // Test that the payload generated is equivalent
    pretty_assertions::assert_str_eq!(
        format!("{:?}", &empty_rpm.content.as_bstr()),
        format!("{:?}", &built_empty_rpm.content.as_bstr()),
    );

    Ok(())
}
