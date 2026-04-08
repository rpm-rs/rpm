//! # rpm-rs
//!
//! A pure Rust library for parsing and creating RPM files.
//!
//! ## Features
//!
//! - Easy to use API
//! - Pure Rust for easy integration in larger projects
//! - Independence of spec files - pure programmatic interface for packaging
//! - Compatibility from Enterprise Linux 8 (RHEL, Alma, Rocky, CentOS Stream) to Fedora
//!
//! All supported compression types are behind feature flags. All of them except bzip2 are enabled
//! by default. They can be disabled if these compression algorithms are unused.
//!
//! ## Examples
//!
//! ### Read package and access metadata
//!
//! ```
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let pkg = rpm::Package::open("tests/assets/RPMS/v6/rpm-basic-2.3.4-5.el9.noarch.rpm")?;
//!
//! let name = pkg.metadata.get_name()?;
//! let version = pkg.metadata.get_version()?;
//! let release = pkg.metadata.get_release()?;
//! let arch = pkg.metadata.get_arch()?;
//!
//! println!("{}-{}-{}.{}", name, version, release, arch);
//!
//! for changelog in pkg.metadata.get_changelog_entries()? {
//!     println!("{}\n{}\n", changelog.name, changelog.description);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ### Sign existing package and verify package signature
//!
//! ```
//! # #[cfg(feature = "signature-pgp")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use rpm::signature::pgp::{Signer, Verifier};
//!
//! let signer = Signer::from_asc_file("./tests/assets/signing_keys/v6/rpm-testkey-v6-rsa4k.secret")?;
//! let verifier = Verifier::from_asc_file("./tests/assets/signing_keys/v6/rpm-testkey-v6-rsa4k.asc")?;
//!
//! let mut pkg = rpm::Package::open("./tests/assets/RPMS/v6/signed/rpm-basic-with-rsa4k-2.3.4-5.el9.noarch.rpm")?;
//! pkg.sign(signer)?;
//! pkg.write_to("./with_signature.rpm")?;
//!
//! let pkg = rpm::Package::open("./with_signature.rpm")?;
//! pkg.verify_signature(verifier)?;
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "signature-pgp"))]
//! # fn main() {}
//! ```
//!
//! ### Sign with a specific subkey
//!
//! ```
//! # #[cfg(feature = "signature-pgp")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use rpm::signature::pgp::Signer;
//!
//! let subkey_fingerprint = hex::decode("715619ae2365d909eb991ff97a509cd76a0bac92f0e17c1c2525812852cedfc5")?;
//!
//! let signer = Signer::from_asc_file("./tests/assets/signing_keys/v6/rpm-testkey-v6-ed25519.secret")?
//!     .with_signing_key(&subkey_fingerprint)?;
//!
//! let mut pkg = rpm::Package::open("./tests/assets/RPMS/v6/rpm-basic-2.3.4-5.el9.noarch.rpm")?;
//! pkg.sign(signer)?;
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "signature-pgp"))]
//! # fn main() {}
//! ```
//!
//! ### Verify using a keyring with multiple certificates
//!
//! ```
//! # #[cfg(feature = "signature-pgp")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use rpm::signature::pgp::Verifier;
//!
//! // Keyring files containing multiple OpenPGP certificates are supported.
//! // The verifier will try each certificate until it finds one that matches.
//! let verifier = Verifier::from_asc_file("./tests/assets/signing_keys/v4/rpm-testkey-v4-keyring.asc")?;
//!
//! let pkg = rpm::Package::open("./tests/assets/RPMS/v4/signed/rpm-basic-with-rsa4096-2.3.4-5.el9.noarch.rpm")?;
//! pkg.verify_signature(verifier)?;
//!
//! // You can also narrow down to a specific certificate by fingerprint:
//! let verifier = Verifier::from_asc_file("./tests/assets/signing_keys/v4/rpm-testkey-v4-keyring.asc")?
//!     .with_key(&hex::decode("D996AEDC0D64D1E621B95AD2E964F9FB30D073B5")?)?;
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "signature-pgp"))]
//! # fn main() {}
//! ```
//!
//! ### Inspect package signatures
//!
//! ```
//! # #[cfg(feature = "signature-pgp")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use rpm::signature::pgp::SignatureVersion;
//!
//! let pkg = rpm::Package::open("./tests/assets/RPMS/v6/signed/rpm-basic-with-rsa4k-2.3.4-5.el9.noarch.rpm")?;
//!
//! for sig in pkg.signatures()? {
//!     println!("Version: {:?}", sig.version());
//!     println!("Algorithm: {:?}", sig.algorithm());
//!     println!("Hash algorithm: {:?}", sig.hash_algorithm());
//!     if let Some(fp) = sig.fingerprint() {
//!         println!("Fingerprint: {}", fp);
//!     }
//!     if let Some(kid) = sig.key_id() {
//!         println!("Key ID: {}", kid);
//!     }
//!     if sig.version() == SignatureVersion::V6 {
//!         println!("This is a v6 signature");
//!     }
//! }
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "signature-pgp"))]
//! # fn main() {}
//! ```
//!
//! ### Detailed verification reports
//!
//! ```
//! # #[cfg(feature = "signature-pgp")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use rpm::signature::pgp::Verifier;
//!
//! let pkg = rpm::Package::open("./tests/assets/RPMS/v6/signed/rpm-basic-with-rsa4k-2.3.4-5.el9.noarch.rpm")?;
//! let verifier = Verifier::from_asc_file("./tests/assets/signing_keys/v6/rpm-testkey-v6-rsa4k.asc")?;
//!
//! let report = pkg.check_signatures(verifier)?;
//!
//! // Inspect individual digest results
//! if report.digests.sha256_header.is_verified() {
//!     println!("SHA-256 header digest: OK");
//! }
//!
//! // Inspect each signature with its metadata
//! for result in &report.signatures {
//!     if let Some(fp) = result.info.fingerprint() {
//!         print!("Signature {}: ", fp);
//!     }
//!     if result.is_verified() {
//!         println!("OK");
//!     } else {
//!         println!("FAILED: {}", result.error.as_ref().unwrap());
//!     }
//! }
//!
//! // Or just check overall pass/fail
//! assert!(report.is_ok());
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "signature-pgp"))]
//! # fn main() {}
//! ```
//!
//! ### Build new package
//!
//! ```
//! # #[cfg(all(unix, feature = "signature-pgp"))]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let _ = env_logger::Builder::new().filter_level(log::LevelFilter::Trace).is_test(true).try_init();
//! use rpm::signature::pgp::Signer;
//!
//! // For reproducible builds, set source_date to the timestamp of the last commit in your VCS
//! let build_config = rpm::BuildConfig::default()
//!     .compression(rpm::CompressionType::Gzip)
//!     .source_date(1_600_000_000);
//! let signer = Signer::from_asc_file("./tests/assets/signing_keys/v6/rpm-testkey-v6-ed25519.secret")?;
//! let pkg = rpm::PackageBuilder::new("test", "1.0.0", "MIT", "x86_64", "some awesome package")
//!     .using_config(build_config)
//!     // set default ownership and permissions for files and directories, similar to %defattr
//!     // in an RPM spec file. Pass None for any field to leave it unchanged (like `-` in %defattr).
//!     .default_file_attrs(Some(0o644), Some("myuser".into()), Some("mygroup".into()))
//!     .default_dir_attrs(Some(0o755), Some("myuser".into()), Some("mygroup".into()))
//!     // add a file with no special options
//!     // by default, files will be owned by the "root" user and group, and inherit their permissions
//!     // from the on-disk file.
//!     .with_file(
//!         "./tests/assets/SOURCES/multiplication_tables.py",
//!         rpm::FileOptions::new("/usr/bin/awesome"),
//!     )?
//!     // you can set permissions, capabilities and other metadata (user, group, etc.) manually
//!     .with_file(
//!         "./tests/assets/SOURCES/example_config.toml",
//!         rpm::FileOptions::new("/etc/awesome/second.toml")
//!             .permissions(0o644)
//!             .caps("cap_sys_admin,cap_net_admin=pe")?
//!             .user("hugo"),
//!     )?
//!     // Add a file - setting flags on it equivalent to `%config(noreplace)`
//!     .with_file(
//!         "./tests/assets/SOURCES/example_config.toml",
//!         rpm::FileOptions::new("/etc/awesome/config.toml")
//!             .config().noreplace(),
//!     )?
//!     // symlinks don't require a source file
//!     .with_symlink(
//!         rpm::FileOptions::symlink("/usr/bin/awesome_link", "/usr/bin/awesome"),
//!     )?
//!     // directories can be created with explicit ownership and permissions
//!     // this does not add any directory contents, just declares a directory
//!     .with_dir_entry(
//!         rpm::FileOptions::dir("/var/log/awesome").permissions(0o750),
//!     )?
//!     // ghost files / directories are not included in the package payload, but their metadata
//!     // (ownership, permissions, etc.) is tracked by RPM. This is commonly used for files
//!     // created at runtime (e.g. log files, PID files).
//!     .with_ghost(
//!         rpm::FileOptions::ghost("/var/log/awesome/app.log"),
//!     )?
//!     .pre_install_script("echo preinst")
//!     // Alternatively, use scriptlet builder api to specify flags and interpreter/arguments
//!     .post_trans_script(
//!         rpm::Scriptlet::new("echo posttrans")
//!             .flags(rpm::ScriptletFlags::EXPAND)
//!             .prog(vec!["/bin/blah/bash", "-c"])
//!     )
//!     .build_host(gethostname::gethostname().to_str().unwrap_or("host"))
//!     .add_changelog_entry(
//!         "Max Mustermann <max@example.com> - 0.1-29",
//!         "- was awesome, eh?",
//!         chrono::DateTime::parse_from_rfc2822("Wed, 19 Apr 2023 23:16:09 GMT")
//!             .expect("Date 1 is correct. qed"),
//!     )
//!     .add_changelog_entry(
//!         "Charlie Yom <test2@example.com> - 0.1-28",
//!         "- yeah, it was",
//!         // Raw timestamp for 1996-08-14 05:20:00
//!         840_000_000,
//!     )
//!     .requires(rpm::Dependency::any("wget"))
//!     .vendor("corporation or individual")
//!     .url("www.github.com/repo")
//!     .vcs("git:repo=example_repo:branch=example_branch:sha=example_sha")
//!     .build_and_sign(signer)?;
//!
//! // Write to a specific file
//! pkg.write_to("./target/awesome.rpm")?;
//!
//! // Or write to a directory with auto-generated filename (`target/awesome-1.0.0-1.x86_64.rpm`)
//! pkg.write_to("./target")?;
//! # Ok(())
//! # }
//! # #[cfg(not(all(unix, feature = "signature-pgp")))]
//! # fn main() {}
//! ```

#![allow(unknown_lints, clippy::uninlined_format_args)]

mod errors;
pub use crate::errors::*;

pub(crate) mod constants;
pub use crate::constants::*;

mod version;
pub use crate::version::*;

mod rpm;
pub use crate::rpm::*;
