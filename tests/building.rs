use std::path::Path;

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
