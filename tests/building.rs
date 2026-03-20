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

/// Verify that each `with_*` method rejects mismatched `FileOptions` variants.
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

/// Round-trip a package using all `with_*` entry types and verify their metadata is preserved.
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
                assert_eq!(entry.mode.file_type(), FileType::Regular);
                assert_eq!(entry.mode.permissions(), 0o644);
            }
            "/usr/bin/test_link" => {
                assert_eq!(entry.mode.file_type(), FileType::SymbolicLink);
                assert_eq!(&entry.linkto, "/usr/bin/test_target");
            }
            "/var/log/testapp" => {
                assert_eq!(entry.mode.file_type(), FileType::Dir);
                assert_eq!(entry.mode.permissions(), 0o750);
            }
            "/var/log/testapp/app.log" => {
                assert!(entry.flags.contains(FileFlags::GHOST));
                assert_eq!(entry.mode.file_type(), FileType::Regular);
            }
            "/var/run/testapp" => {
                assert!(entry.flags.contains(FileFlags::GHOST));
                assert_eq!(entry.mode.file_type(), FileType::Dir);
            }
            _ => {}
        }
    }

    Ok(())
}

/// Verify that `with_dir_contents` recursively adds directory entries and files.
#[test]
fn test_with_dir_contents_basic() -> Result<(), Box<dyn std::error::Error>> {
    let source_dir = Path::new(common::CARGO_MANIFEST_DIR).join("tests/assets/SOURCES/module");

    let pkg = PackageBuilder::new("test-dir", "1.0.0", "MIT", "x86_64", "test")
        .source_date(1_600_000_000)
        .with_dir_contents(&source_dir, "/usr/lib/mymodule", |o| o)?
        .build()?;

    let mut buf = Vec::new();
    pkg.write(&mut buf)?;
    let parsed = Package::parse(&mut buf.as_slice())?;
    let entries = parsed.metadata.get_file_entries()?;
    let paths: Vec<_> = entries.iter().map(|e| e.path.as_path()).collect();

    // Should have directory entry + 2 files
    assert_eq!(
        paths,
        vec![
            Path::new("/usr/lib/mymodule"),
            Path::new("/usr/lib/mymodule/__init__.py"),
            Path::new("/usr/lib/mymodule/hello.py"),
        ]
    );

    // Directory entry
    assert_eq!(entries[0].mode.file_type(), FileType::Dir);
    assert_eq!(entries[0].size, 0);

    // Files should be regular
    assert_eq!(entries[1].mode.file_type(), FileType::Regular);
    assert_eq!(entries[2].mode.file_type(), FileType::Regular);

    Ok(())
}

/// An explicit `with_file` added before `with_dir_contents` should take priority over the bulk add.
#[test]
fn test_with_dir_contents_explicit_override_before_bulk() -> Result<(), Box<dyn std::error::Error>>
{
    let source_dir = Path::new(common::CARGO_MANIFEST_DIR).join("tests/assets/SOURCES/module");
    let init_file = source_dir.join("__init__.py");

    // Add __init__.py explicitly with config flag, then bulk-add the directory.
    // The explicit entry should win (bulk skips existing).
    let pkg = PackageBuilder::new("test-dir", "1.0.0", "MIT", "x86_64", "test")
        .source_date(1_600_000_000)
        .with_file(
            &init_file,
            FileOptions::new("/usr/lib/mymodule/__init__.py").config(),
        )?
        .with_dir_contents(&source_dir, "/usr/lib/mymodule", |o| o)?
        .build()?;

    let mut buf = Vec::new();
    pkg.write(&mut buf)?;
    let parsed = Package::parse(&mut buf.as_slice())?;
    let entries = parsed.metadata.get_file_entries()?;

    let init_entry = entries
        .iter()
        .find(|e| e.path == Path::new("/usr/lib/mymodule/__init__.py"))
        .expect("__init__.py should be present");

    // The explicitly-added CONFIG flag should be preserved (not overwritten by bulk)
    assert!(init_entry.flags.contains(FileFlags::CONFIG));

    Ok(())
}

/// An explicit `with_file` added after `with_dir_contents` should replace the bulk-added entry.
#[test]
fn test_with_dir_contents_explicit_override_after_bulk() -> Result<(), Box<dyn std::error::Error>> {
    let source_dir = Path::new(common::CARGO_MANIFEST_DIR).join("tests/assets/SOURCES/module");
    let init_file = source_dir.join("__init__.py");

    // Bulk-add first, then override __init__.py explicitly.
    // The explicit entry should replace the bulk-added one.
    let pkg = PackageBuilder::new("test-dir", "1.0.0", "MIT", "x86_64", "test")
        .source_date(1_600_000_000)
        .with_dir_contents(&source_dir, "/usr/lib/mymodule", |o| o)?
        .with_file(
            &init_file,
            FileOptions::new("/usr/lib/mymodule/__init__.py").config(),
        )?
        .build()?;

    let mut buf = Vec::new();
    pkg.write(&mut buf)?;
    let parsed = Package::parse(&mut buf.as_slice())?;
    let entries = parsed.metadata.get_file_entries()?;

    let init_entry = entries
        .iter()
        .find(|e| e.path == Path::new("/usr/lib/mymodule/__init__.py"))
        .expect("__init__.py should be present");

    // The explicit CONFIG flag should be present (replaced the bulk entry)
    assert!(init_entry.flags.contains(FileFlags::CONFIG));

    Ok(())
}

/// When two `with_dir_contents` calls cover the same path, the first bulk add wins.
#[test]
fn test_with_dir_contents_overlapping_bulk_first_wins() -> Result<(), Box<dyn std::error::Error>> {
    let source_dir = Path::new(common::CARGO_MANIFEST_DIR).join("tests/assets/SOURCES/module");

    // Two bulk adds of the same directory — first one wins
    let pkg = PackageBuilder::new("test-dir", "1.0.0", "MIT", "x86_64", "test")
        .source_date(1_600_000_000)
        .with_dir_contents(&source_dir, "/usr/lib/mymodule", |o| o.config())?
        .with_dir_contents(&source_dir, "/usr/lib/mymodule", |o| o.doc())?
        .build()?;

    let mut buf = Vec::new();
    pkg.write(&mut buf)?;
    let parsed = Package::parse(&mut buf.as_slice())?;
    let entries = parsed.metadata.get_file_entries()?;

    let init_entry = entries
        .iter()
        .find(|e| e.path == Path::new("/usr/lib/mymodule/__init__.py"))
        .expect("__init__.py should be present");

    // First bulk add used config(), second used doc(). First should win.
    assert!(init_entry.flags.contains(FileFlags::CONFIG));
    assert!(!init_entry.flags.contains(FileFlags::DOC));

    Ok(())
}

/// Adding the same path explicitly twice should produce an error.
#[test]
fn test_duplicate_explicit_add_still_errors() {
    let cargo_file = Path::new(common::CARGO_MANIFEST_DIR).join("Cargo.toml");

    let result = PackageBuilder::new("test-dup", "1.0.0", "MIT", "x86_64", "test")
        .with_file(&cargo_file, FileOptions::new("/etc/test.toml"))
        .unwrap()
        .with_file(&cargo_file, FileOptions::new("/etc/test.toml"));

    assert!(result.is_err(), "duplicate explicit add should error");
}

/// File-only flags like CONFIG applied via the `customize` callback should be stripped from directory entries.
#[test]
fn test_with_dir_contents_strips_flags_from_dirs() -> Result<(), Box<dyn std::error::Error>> {
    let source_dir = Path::new(common::CARGO_MANIFEST_DIR).join("tests/assets/SOURCES/module");

    // Customize callback adds CONFIG — should be stripped from the directory entry
    // but preserved on the file entries
    let pkg = PackageBuilder::new("test-dir", "1.0.0", "MIT", "x86_64", "test")
        .source_date(1_600_000_000)
        .with_dir_contents(&source_dir, "/usr/lib/mymodule", |o| o.config())?
        .build()?;

    let mut buf = Vec::new();
    pkg.write(&mut buf)?;
    let parsed = Package::parse(&mut buf.as_slice())?;
    let entries = parsed.metadata.get_file_entries()?;

    let dir_entry = entries
        .iter()
        .find(|e| e.path == Path::new("/usr/lib/mymodule"))
        .expect("directory entry should be present");
    assert_eq!(dir_entry.mode.file_type(), FileType::Dir);
    assert!(
        !dir_entry.flags.contains(FileFlags::CONFIG),
        "CONFIG should be stripped from directory entries"
    );

    let file_entry = entries
        .iter()
        .find(|e| e.path == Path::new("/usr/lib/mymodule/hello.py"))
        .expect("hello.py should be present");
    assert!(
        file_entry.flags.contains(FileFlags::CONFIG),
        "CONFIG should be preserved on file entries"
    );

    Ok(())
}

/// Default file attrs should apply permissions, user, and group to files when not explicitly set.
#[test]
fn test_default_file_attrs() -> Result<(), Box<dyn std::error::Error>> {
    let cargo_file = Path::new(common::CARGO_MANIFEST_DIR).join("Cargo.toml");

    let pkg = PackageBuilder::new("test-defaults", "1.0.0", "MIT", "x86_64", "test")
        .default_file_attrs(Some(0o755), Some("myuser".into()), Some("mygroup".into()))
        .with_file(&cargo_file, FileOptions::new("/usr/bin/myapp"))?
        .build()?;

    let mut buf = Vec::new();
    pkg.write(&mut buf)?;
    let parsed = Package::parse(&mut buf.as_slice())?;
    let entries = parsed.metadata.get_file_entries()?;

    let entry = entries
        .iter()
        .find(|e| e.path == Path::new("/usr/bin/myapp"))
        .expect("file should be present");

    assert_eq!(entry.mode.permissions(), 0o755);
    assert_eq!(entry.ownership.user, "myuser");
    assert_eq!(entry.ownership.group, "mygroup");

    Ok(())
}

/// Default dir attrs should apply permissions, user, and group to directories when not explicitly set.
#[test]
fn test_default_dir_attrs() -> Result<(), Box<dyn std::error::Error>> {
    let pkg = PackageBuilder::new("test-defaults", "1.0.0", "MIT", "x86_64", "test")
        .default_dir_attrs(Some(0o700), Some("diruser".into()), Some("dirgroup".into()))
        .with_dir(FileOptions::dir("/var/log/myapp"))?
        .build()?;

    let mut buf = Vec::new();
    pkg.write(&mut buf)?;
    let parsed = Package::parse(&mut buf.as_slice())?;
    let entries = parsed.metadata.get_file_entries()?;

    let entry = entries
        .iter()
        .find(|e| e.path == Path::new("/var/log/myapp"))
        .expect("dir should be present");

    assert_eq!(entry.mode.permissions(), 0o700);
    assert_eq!(entry.ownership.user, "diruser");
    assert_eq!(entry.ownership.group, "dirgroup");

    Ok(())
}

/// File defaults and dir defaults should apply independently to the correct entry types.
#[test]
fn test_default_attrs_file_vs_dir() -> Result<(), Box<dyn std::error::Error>> {
    let cargo_file = Path::new(common::CARGO_MANIFEST_DIR).join("Cargo.toml");

    let pkg = PackageBuilder::new("test-defaults", "1.0.0", "MIT", "x86_64", "test")
        .default_file_attrs(
            Some(0o644),
            Some("fileuser".into()),
            Some("filegroup".into()),
        )
        .default_dir_attrs(Some(0o755), Some("diruser".into()), Some("dirgroup".into()))
        .with_file(&cargo_file, FileOptions::new("/etc/myapp.conf"))?
        .with_dir(FileOptions::dir("/var/log/myapp"))?
        .build()?;

    let mut buf = Vec::new();
    pkg.write(&mut buf)?;
    let parsed = Package::parse(&mut buf.as_slice())?;
    let entries = parsed.metadata.get_file_entries()?;

    let file_entry = entries
        .iter()
        .find(|e| e.path == Path::new("/etc/myapp.conf"))
        .expect("file should be present");
    assert_eq!(file_entry.mode.permissions(), 0o644);
    assert_eq!(file_entry.ownership.user, "fileuser");
    assert_eq!(file_entry.ownership.group, "filegroup");

    let dir_entry = entries
        .iter()
        .find(|e| e.path == Path::new("/var/log/myapp"))
        .expect("dir should be present");
    assert_eq!(dir_entry.mode.permissions(), 0o755);
    assert_eq!(dir_entry.ownership.user, "diruser");
    assert_eq!(dir_entry.ownership.group, "dirgroup");

    Ok(())
}

/// Explicit FileOptions should override default attrs.
#[test]
fn test_default_attrs_explicit_override() -> Result<(), Box<dyn std::error::Error>> {
    let cargo_file = Path::new(common::CARGO_MANIFEST_DIR).join("Cargo.toml");

    let pkg = PackageBuilder::new("test-defaults", "1.0.0", "MIT", "x86_64", "test")
        .default_file_attrs(
            Some(0o755),
            Some("defaultuser".into()),
            Some("defaultgroup".into()),
        )
        .with_file(
            &cargo_file,
            FileOptions::new("/usr/bin/myapp")
                .permissions(0o700)
                .user("explicituser")
                .group("explicitgroup"),
        )?
        .build()?;

    let mut buf = Vec::new();
    pkg.write(&mut buf)?;
    let parsed = Package::parse(&mut buf.as_slice())?;
    let entries = parsed.metadata.get_file_entries()?;

    let entry = entries
        .iter()
        .find(|e| e.path == Path::new("/usr/bin/myapp"))
        .expect("file should be present");

    assert_eq!(entry.mode.permissions(), 0o700);
    assert_eq!(entry.ownership.user, "explicituser");
    assert_eq!(entry.ownership.group, "explicitgroup");

    Ok(())
}

/// Calling default_file_attrs multiple times should accumulate — later calls override earlier ones.
#[test]
fn test_default_attrs_called_twice() -> Result<(), Box<dyn std::error::Error>> {
    let cargo_file = Path::new(common::CARGO_MANIFEST_DIR).join("Cargo.toml");

    let pkg = PackageBuilder::new("test-defaults", "1.0.0", "MIT", "x86_64", "test")
        .default_file_attrs(Some(0o644), Some("user1".into()), Some("group1".into()))
        .default_file_attrs(Some(0o755), None, None)
        .with_file(&cargo_file, FileOptions::new("/usr/bin/myapp"))?
        .build()?;

    let mut buf = Vec::new();
    pkg.write(&mut buf)?;
    let parsed = Package::parse(&mut buf.as_slice())?;
    let entries = parsed.metadata.get_file_entries()?;

    let entry = entries
        .iter()
        .find(|e| e.path == Path::new("/usr/bin/myapp"))
        .expect("file should be present");

    // Second call overrode permissions; user/group were None so first call's values persist
    assert_eq!(entry.mode.permissions(), 0o755);
    assert_eq!(entry.ownership.user, "user1");
    assert_eq!(entry.ownership.group, "group1");

    Ok(())
}

/// None fields in default attrs should leave the default (root) unchanged.
#[test]
fn test_default_attrs_none_fields() -> Result<(), Box<dyn std::error::Error>> {
    let cargo_file = Path::new(common::CARGO_MANIFEST_DIR).join("Cargo.toml");

    let pkg = PackageBuilder::new("test-defaults", "1.0.0", "MIT", "x86_64", "test")
        .default_file_attrs(None, Some("myuser".into()), None)
        .with_file(&cargo_file, FileOptions::new("/usr/bin/myapp"))?
        .build()?;

    let mut buf = Vec::new();
    pkg.write(&mut buf)?;
    let parsed = Package::parse(&mut buf.as_slice())?;
    let entries = parsed.metadata.get_file_entries()?;

    let entry = entries
        .iter()
        .find(|e| e.path == Path::new("/usr/bin/myapp"))
        .expect("file should be present");

    assert_eq!(entry.ownership.user, "myuser");
    assert_eq!(entry.ownership.group, "root");

    Ok(())
}

/// Default attrs should apply to files added via `with_dir_contents`.
#[test]
fn test_default_attrs_with_dir_contents() -> Result<(), Box<dyn std::error::Error>> {
    let source_dir = Path::new(common::CARGO_MANIFEST_DIR).join("tests/assets/SOURCES/module");

    let pkg = PackageBuilder::new("test-defaults", "1.0.0", "MIT", "x86_64", "test")
        .source_date(1_600_000_000)
        .default_file_attrs(Some(0o644), Some("fileuser".into()), None)
        .default_dir_attrs(Some(0o755), Some("diruser".into()), None)
        .with_dir_contents(&source_dir, "/usr/lib/mymodule", |o| o)?
        .build()?;

    let mut buf = Vec::new();
    pkg.write(&mut buf)?;
    let parsed = Package::parse(&mut buf.as_slice())?;
    let entries = parsed.metadata.get_file_entries()?;

    let dir_entry = entries
        .iter()
        .find(|e| e.path == Path::new("/usr/lib/mymodule"))
        .expect("dir should be present");
    assert_eq!(dir_entry.mode.permissions(), 0o755);
    assert_eq!(dir_entry.ownership.user, "diruser");

    let file_entry = entries
        .iter()
        .find(|e| e.path == Path::new("/usr/lib/mymodule/hello.py"))
        .expect("file should be present");
    assert_eq!(file_entry.mode.permissions(), 0o644);
    assert_eq!(file_entry.ownership.user, "fileuser");

    Ok(())
}
