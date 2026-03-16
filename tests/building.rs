use std::path::{Path, PathBuf};

use rpm::*;

mod common;

/// Ensure control characters (except tab/newline in descriptions) are rejected in package metadata fields.
#[test]
fn test_reject_control_chars_in_metadata() {
    // Control character in name
    let result = PackageBuilder::new("foo\x07bar", "1.0.0", "MIT", "x86_64", "test").build();
    assert!(result.is_err(), "should reject control chars in name");

    // Control character in version
    let result = PackageBuilder::new("foo", "1.0\x01.0", "MIT", "x86_64", "test").build();
    assert!(result.is_err(), "should reject control chars in version");

    // Control character in summary
    let result = PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "test\x1b[0m").build();
    assert!(
        result.is_err(),
        "should reject control chars (ANSI escape) in summary"
    );

    // Tab and newline are allowed in description
    let result = PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "test")
        .description("line1\nline2\ttabbed")
        .build();
    assert!(
        result.is_ok(),
        "tabs and newlines should be allowed in description"
    );

    // Control character in dependency name
    let result = PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "test")
        .requires(rpm::Dependency::any("bad\x00dep"))
        .build();
    assert!(
        result.is_err(),
        "should reject control chars in dependency name"
    );

    // Control character in changelog
    let result = PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "test")
        .add_changelog_entry("author\x07 <a@b.c>", "entry", 1_600_000_000)
        .build();
    assert!(
        result.is_err(),
        "should reject control chars in changelog name"
    );

    // DEL (0x7F) should be rejected in name
    let result = PackageBuilder::new("foo\x7f", "1.0.0", "MIT", "x86_64", "test").build();
    assert!(result.is_err(), "should reject DEL in name");
}

/// Validate that package names allow only permitted characters and reject invalid ones.
#[test]
fn test_validate_name_characters() {
    // Valid names
    assert!(
        PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "t")
            .build()
            .is_ok()
    );
    assert!(
        PackageBuilder::new("foo-bar", "1.0.0", "MIT", "x86_64", "t")
            .build()
            .is_ok()
    );
    assert!(
        PackageBuilder::new("foo_bar", "1.0.0", "MIT", "x86_64", "t")
            .build()
            .is_ok()
    );
    assert!(
        PackageBuilder::new("foo.bar", "1.0.0", "MIT", "x86_64", "t")
            .build()
            .is_ok()
    );
    assert!(
        PackageBuilder::new("foo+bar", "1.0.0", "MIT", "x86_64", "t")
            .build()
            .is_ok()
    );
    assert!(
        PackageBuilder::new("_foo", "1.0.0", "MIT", "x86_64", "t")
            .build()
            .is_ok()
    );
    assert!(
        PackageBuilder::new("%{name}", "1.0.0", "MIT", "x86_64", "t")
            .build()
            .is_ok()
    );

    // Invalid: whitespace in name
    let result = PackageBuilder::new("foo bar", "1.0.0", "MIT", "x86_64", "t").build();
    assert!(result.is_err(), "should reject whitespace in name");

    // Invalid: empty name
    let result = PackageBuilder::new("", "1.0.0", "MIT", "x86_64", "t").build();
    assert!(result.is_err(), "should reject empty name");

    // Invalid: starts with hyphen
    let result = PackageBuilder::new("-foo", "1.0.0", "MIT", "x86_64", "t").build();
    assert!(result.is_err(), "should reject name starting with hyphen");

    // Invalid: special characters
    let result = PackageBuilder::new("foo@bar", "1.0.0", "MIT", "x86_64", "t").build();
    assert!(result.is_err(), "should reject @ in name");
}

/// Validate that version and release strings allow only permitted characters and reject invalid ones.
#[test]
fn test_validate_version_characters() {
    // Valid versions
    assert!(
        PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "t")
            .build()
            .is_ok()
    );
    assert!(
        PackageBuilder::new("foo", "1.0.0~rc1", "MIT", "x86_64", "t")
            .build()
            .is_ok()
    );
    assert!(
        PackageBuilder::new("foo", "1.0.0^post1", "MIT", "x86_64", "t")
            .build()
            .is_ok()
    );
    assert!(
        PackageBuilder::new("foo", "1.0+git123", "MIT", "x86_64", "t")
            .build()
            .is_ok()
    );

    // Invalid: hyphen in version (allowed in name but not version)
    let result = PackageBuilder::new("foo", "1.0-beta", "MIT", "x86_64", "t").build();
    assert!(result.is_err(), "should reject hyphen in version");

    // Invalid: whitespace in version
    let result = PackageBuilder::new("foo", "1.0 0", "MIT", "x86_64", "t").build();
    assert!(result.is_err(), "should reject whitespace in version");

    // Invalid: empty version
    let result = PackageBuilder::new("foo", "", "MIT", "x86_64", "t").build();
    assert!(result.is_err(), "should reject empty version");

    // Invalid: release with hyphen
    let result = PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "t")
        .release("1-beta")
        .build();
    assert!(result.is_err(), "should reject hyphen in release");
}

/// Ensure control characters are rejected in file-level metadata such as owner names.
#[test]
fn test_reject_control_chars_in_file_metadata() {
    let cargo_file = Path::new(common::CARGO_MANIFEST_DIR).join("Cargo.toml");

    // Control character in file owner
    let result = PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "test")
        .with_file(
            &cargo_file,
            FileOptions::new("/etc/test.toml").user("bad\x01user"),
        )
        .unwrap()
        .build();
    assert!(result.is_err(), "should reject control chars in file user");
}


#[test]
fn test_file_options_validation() {
    let cargo_file = Path::new(common::CARGO_MANIFEST_DIR).join("Cargo.toml");

    // with_dir rejects non-Dir mode
    let err = PackageBuilder::new("t", "1.0.0", "MIT", "x86_64", "t")
        .with_dir(FileOptions::new("/var/log/foo"));
    assert!(err.is_err(), "with_dir should reject regular file options");

    // with_symlink rejects non-SymbolicLink mode
    let err = PackageBuilder::new("t", "1.0.0", "MIT", "x86_64", "t")
        .with_symlink(FileOptions::new("/usr/bin/link"));
    assert!(
        err.is_err(),
        "with_symlink should reject regular file options"
    );

    // with_symlink rejects empty target
    let err = PackageBuilder::new("t", "1.0.0", "MIT", "x86_64", "t")
        .with_symlink(FileOptions::new("/usr/bin/link").mode(FileMode::symbolic_link(0o777)));
    assert!(
        err.is_err(),
        "with_symlink should reject empty symlink target"
    );

    // with_ghost rejects non-ghost options
    let err = PackageBuilder::new("t", "1.0.0", "MIT", "x86_64", "t")
        .with_ghost(FileOptions::new("/var/log/foo"));
    assert!(err.is_err(), "with_ghost should reject non-ghost options");

    // with_file rejects Dir mode
    let err = PackageBuilder::new("t", "1.0.0", "MIT", "x86_64", "t").with_file(
        cargo_file.to_str().unwrap(),
        FileOptions::dir("/var/log/foo"),
    );
    assert!(err.is_err(), "with_file should reject directory options");

    // with_file rejects ghost flag
    let err = PackageBuilder::new("t", "1.0.0", "MIT", "x86_64", "t").with_file(
        cargo_file.to_str().unwrap(),
        FileOptions::ghost("/var/log/foo"),
    );
    assert!(err.is_err(), "with_file should reject ghost options");

    // with_file_contents rejects Dir mode
    let err = PackageBuilder::new("t", "1.0.0", "MIT", "x86_64", "t")
        .with_file_contents("content", FileOptions::dir("/var/log/foo"));
    assert!(
        err.is_err(),
        "with_file_contents should reject directory options"
    );

    // with_file_contents rejects ghost flag
    let err = PackageBuilder::new("t", "1.0.0", "MIT", "x86_64", "t")
        .with_file_contents("content", FileOptions::ghost("/var/log/foo"));
    assert!(
        err.is_err(),
        "with_file_contents should reject ghost options"
    );
}

#[test]
fn test_build_with_new_file_api() -> Result<(), Box<dyn std::error::Error>> {
    let cargo_file = Path::new(common::CARGO_MANIFEST_DIR).join("Cargo.toml");

    let pkg = PackageBuilder::new("test-new-api", "1.0.0", "MIT", "x86_64", "test package")
        // Regular file with the new permissions() method
        .with_file(
            cargo_file.to_str().unwrap(),
            FileOptions::new("/etc/test/config.toml")
                .permissions(0o644)
                .config(),
        )?
        // Symlink via dedicated constructor and method
        .with_symlink(FileOptions::symlink(
            "/usr/bin/test_link",
            "/usr/bin/test_target",
        ))?
        // Explicit directory entry
        .with_dir(
            FileOptions::dir("/var/log/testapp")
                .permissions(0o750)
                .user("testuser"),
        )?
        // Ghost file
        .with_ghost(FileOptions::ghost("/var/log/testapp/app.log").permissions(0o644))?
        // Ghost directory
        .with_ghost(FileOptions::ghost_dir("/var/run/testapp"))?
        .build()?;

    // Write and re-read the package
    let mut buf = Vec::new();
    pkg.write(&mut buf)?;
    let parsed = Package::parse(&mut buf.as_slice())?;
    let metadata = &parsed.metadata;

    let file_paths = metadata.get_file_paths()?;
    let file_entries = metadata.get_file_entries()?;

    // Verify all entries are present
    assert!(file_paths.contains(&PathBuf::from("/etc/test/config.toml")));
    assert!(file_paths.contains(&PathBuf::from("/usr/bin/test_link")));
    assert!(file_paths.contains(&PathBuf::from("/var/log/testapp")));
    assert!(file_paths.contains(&PathBuf::from("/var/log/testapp/app.log")));
    assert!(file_paths.contains(&PathBuf::from("/var/run/testapp")));

    // Verify file entry metadata
    for entry in &file_entries {
        match entry.path.to_str().unwrap() {
            "/etc/test/config.toml" => {
                assert!(entry.flags.contains(FileFlags::CONFIG));
                assert!(matches!(entry.mode, FileMode::Regular { .. }));
                assert_eq!(entry.mode.permissions(), 0o644);
            }
            "/usr/bin/test_link" => {
                assert!(matches!(entry.mode, FileMode::SymbolicLink { .. }));
                assert_eq!(&entry.linkto, "/usr/bin/test_target");
            }
            "/var/log/testapp" => {
                assert!(matches!(entry.mode, FileMode::Dir { .. }));
                assert_eq!(entry.mode.permissions(), 0o750);
            }
            "/var/log/testapp/app.log" => {
                assert!(entry.flags.contains(FileFlags::GHOST));
                assert!(matches!(entry.mode, FileMode::Regular { .. }));
            }
            "/var/run/testapp" => {
                assert!(entry.flags.contains(FileFlags::GHOST));
                assert!(matches!(entry.mode, FileMode::Dir { .. }));
            }
            _ => {}
        }
    }

    Ok(())
}
