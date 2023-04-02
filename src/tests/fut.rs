#![cfg(feature = "async-futures")]

use super::*;

#[tokio::test]
async fn test_rpm_header_async() -> Result<(), Box<dyn std::error::Error>> {
    use tokio_util::compat::TokioAsyncReadCompatExt;

    let rpm_file_path = test_rpm_file_path();
    let mut rpm_file = tokio::fs::File::open(rpm_file_path).await?.compat();
    let package = RPMPackage::parse_async(&mut rpm_file).await?;
    test_rpm_header_base(package)
}

#[tokio::test]
async fn test_rpm_builder_async() -> Result<(), Box<dyn std::error::Error>> {
    use std::str::FromStr;

    let mut buff = std::io::Cursor::new(Vec::<u8>::new());

    let pkg = rpm::RPMBuilder::new("test", "1.0.0", "MIT", "x86_64", "some awesome package")
        .compression(rpm::Compressor::from_str("gzip")?)
        .with_file_async(
            "Cargo.toml",
            RPMFileOptions::new("/etc/awesome/config.toml").is_config(),
        )
        .await?
        // file mode is inherited from source file
        .with_file_async("Cargo.toml", RPMFileOptions::new("/usr/bin/awesome"))
        .await?
        .with_file_async(
            "Cargo.toml",
            // you can set a custom mode and custom user too
            RPMFileOptions::new("/etc/awesome/second.toml")
                .mode(0o100744)
                .user("hugo"),
        )
        .await?
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
