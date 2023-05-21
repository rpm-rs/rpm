[![crates.io](https://img.shields.io/crates/v/rpm.svg)](https://crates.io/crates/rpm)
[![docs.rs](https://docs.rs/rpm/badge.svg)](https://docs.rs/rpm)
[![MSRV](https://img.shields.io/badge/rustc-1.65.0+-ab6000.svg)](https://blog.rust-lang.org/2022/11/03/Rust-1.65.0.html)

## RPM-RS

A pure rust library for parsing and creating RPM files.

### Goals

- Easy to use API
- Pure rust to make it easy to use in larger Projects
- Independence of Spec files. Pure programmatic interface for Packaging.
- Compatibility to Centos 7 / Fedora (I may extend test cases for SUSE)

### Non Goals

RPM has a lot of cryptic features. I do not want to re-implement all of them. This library focuses on
the ones that I assume as useful.
This library does not build software like rpmbuild. It is meant for finished artifacts that need to be packaged as RPM.

### Status

- [x] RPM Creation
- [x] Basic RPM Reading
- [x] RPM Signing and Signature Verification
- [x] High Level API for RPM Reading

### Examples

```rust
use rpm;
use rpm::signature::pgp::{Signer,Verifier};

let raw_secret_key = std::fs::read("/path/to/gpg.secret.key")?;
let pkg = rpm::RPMBuilder::new("test", "1.0.0", "MIT", "x86_64", "some awesome package")
            .compression(rpm::CompressionType::Zstd)
            .with_file(
                "./awesome-config.toml",
                rpm::RPMFileOptions::new("/etc/awesome/config.toml").is_config(),
            )?
            // file mode is inherited from source file
            .with_file(
                "./awesome-bin",
                rpm::RPMFileOptions::new("/usr/bin/awesome"),
            )?
             .with_file(
                "./awesome-config.toml",
                // you can set a custom mode and custom user too
                rpm::RPMFileOptions::new("/etc/awesome/second.toml").mode(0o100744).user("hugo"),
            )?
            .pre_install_script("echo preinst")
            .add_changelog_entry("Max Mustermann <max@example.com>", "- was awesome, eh?", chrono::DateTime::parse_from_rfc2822("Wed, 19 April 2023 23:16:09 GMT"))
            .add_changelog_entry("Charlie Yom <test2@example.com>", "- yeah, it was", chrono::DateTime::parse_from_rfc3339("1996-12-19T16:39:57-08:00"))
            .requires(rpm::Dependency::any("wget"))
            .vendor("corporation or individual")
            .url("www.github.com/repo")
            .vcs("git:repo=example_repo:branch=example_branch:sha=example_sha")
            .build_and_sign(Signer::load_from_asc_bytes(&raw_secret_key)?);

pkg.write_file("./awesome.rpm")?;

// reading
let raw_pub_key = std::fs::read("/path/to/gpg.key.pub")?;
let pkg = rpm::RPMPackage::open("test_assets/389-ds-base-devel-1.3.8.4-15.el7.x86_64.rpm")?;

let name = pkg.metadata.get_name()?;
let version = pkg.metadata.get_version()?;
let release = pkg.metadata.get_release()?;
let arch = pkg.metadata.get_arch()?;

println!("{}-{}-{}.{}", name, version, release, arch);

for changelog in pkg.metadata.get_changelog_entries()? {
    println!("{}\n{}\n", changelog.name, changelog.description);
}

// verifying
pkg.verify_signature(Verifier::load_from_asc_bytes(&raw_pub_key)?)?;
```
