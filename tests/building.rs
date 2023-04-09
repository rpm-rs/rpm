use std::io::Cursor;

use bstr::ByteSlice;
use pretty_assertions;

use rpm::*;

mod common;

/// Build an empty package and compare it to one built by rpmbuild
#[test]
fn test_empty_package_equivalent() -> Result<(), Box<dyn std::error::Error>> {
    let empty_rpm = RPMPackage::open(common::rpm_empty_path())?;
    let built_empty_rpm = RPMBuilder::new("rpm-empty", "0", "LGPL", "x86-64", "").build()?;

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

/// Build an empty source package and compare it to one built by rpmbuild
/// Blocked on completion of source package support
#[ignore = "https://github.com/rpm-rs/rpm/issues/66"]
#[test]
fn test_empty_source_package_equivalent() -> Result<(), Box<dyn std::error::Error>> {
    let empty_rpm = RPMPackage::open(common::rpm_empty_source_path())?;
    let built_empty_rpm = RPMBuilder::new("rpm-empty", "0", "LGPL", "x86-64", "").build()?;

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

// @todo: turn this into a comparison test for the rpm-feature-coverage RPM
/// Build an RPM using many features of RPM and (eventually) compare it to one built by rpmbuild
#[test]
fn test_rpm_builder() -> Result<(), Box<dyn std::error::Error>> {
    use std::str::FromStr;

    let mut buff = Vec::<u8>::new();

    let pkg = rpm::RPMBuilder::new("test", "1.0.0", "MIT", "x86_64", "some awesome package")
        .compression(rpm::Compressor::from_str("gzip")?)
        .with_file(
            "Cargo.toml",
            RPMFileOptions::new("/etc/awesome/config.toml").is_config(),
        )?
        // file mode is inherited from source file
        .with_file("Cargo.toml", RPMFileOptions::new("/usr/bin/awesome"))?
        .with_file(
            "Cargo.toml",
            // you can set a custom mode and custom user too
            RPMFileOptions::new("/etc/awesome/second.toml")
                .mode(0o100744)
                .user("hugo"),
        )?
        .pre_install_script("echo preinst")
        .add_changelog_entry("me", "was awesome, eh?", 123123123)
        .add_changelog_entry("you", "yeah, it was", 12312312)
        .requires(Dependency::any("wget"))
        .vendor("dummy vendor")
        .url("dummy url")
        .vcs("dummy vcs")
        .build()?;

    pkg.write(&mut buff)?;

    Ok(())
}

/// Read a package, write it, and read it back - check for equivalence.
#[test]
fn test_rpm_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = Vec::new();
    let rpm = RPMPackage::open(common::rpm_feature_coverage_pkg_path())?;
    rpm.write(&mut buf)?;
    let roundtripped_rpm = RPMPackage::parse(&mut Cursor::new(buf))?;

    assert_eq!(rpm, roundtripped_rpm);
    Ok(())
}
