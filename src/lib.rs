//! # rpm-rs
//!
//! A library providing API to parse rpms as well as
//! creating rpms from individual files.
//!
//! # Example
//!
//! ```
//! # #[cfg(feature = "signature-pgp")]
//! use rpm::{
//!     signature::pgp::{
//!         Signer,
//!         Verifier
//!     },
//!     chrono::TimeZone,
//! };
//! use std::str::FromStr;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let _ = env_logger::Builder::new().filter_level(log::LevelFilter::Trace).is_test(true).try_init();
//! # #[cfg(feature = "signature-pgp")]
//! # {
//! let raw_secret_key = std::fs::read("./test_assets/secret_key.asc")?;
//! let pkg = rpm::RPMBuilder::new("test", "1.0.0", "MIT", "x86_64", "some awesome package")
//!             .compression(rpm::CompressionType::Gzip)
//!             .with_file(
//!                 "./test_assets/awesome.toml",
//!                 rpm::RPMFileOptions::new("/etc/awesome/config.toml")
//!                     .is_config(),
//!             )?
//!             // file mode is inherited from source file
//!             .with_file(
//!                 "./test_assets/awesome.py",
//!                 rpm::RPMFileOptions::new("/usr/bin/awesome"),
//!             )?
//!             .with_file(
//!                 "./test_assets/awesome.toml",
//!                 // you can set a custom mode and custom user too
//!                 rpm::RPMFileOptions::new("/etc/awesome/second.toml")
//!                         .mode(rpm::FileMode::regular(0o644))
//!                         .user("hugo"),
//!             )?
//!             .pre_install_script("echo preinst")
//!             .build_time(chrono::Utc::now())
//!             .build_host(gethostname::gethostname().to_str().expect("Hostname works. qed").to_string())
//!             .add_changelog_entry("Max Mustermann <max@example.com> - 0.1-29", "- was awesome, eh?", chrono::DateTime::parse_from_rfc2822("Wed, 19 Apr 2023 23:16:09 GMT").expect("Date 1 is correct. qed"))
//!             .add_changelog_entry("Charlie Yom <test2@example.com> - 0.1-28", "- yeah, it was", chrono::DateTime::parse_from_rfc3339("1996-12-19T16:39:57-08:00").expect("Date 2 is corrrect. qed"))
//!             .requires(rpm::Dependency::any("wget"))
//!             .vendor("corporation or individual")
//!             .url("www.github.com/repo")
//!             .vcs("git:repo=example_repo:branch=example_branch:sha=example_sha")
//!             .build_and_sign(
//!                 Signer::load_from_asc_bytes(&raw_secret_key)?
//!             )?;
//! let mut f = std::fs::File::create("./target/awesome.rpm")?;
//! pkg.write(&mut f)?;
//!
//! // reading
//! let raw_pub_key = std::fs::read("./test_assets/public_key.asc")?;
//! let pkg = rpm::RPMPackage::open("./target/awesome.rpm")?;
//! // verifying
//! pkg.verify_signature(Verifier::load_from_asc_bytes(&raw_pub_key)?)?;
//! # }
//! # Ok(())
//! # }
//! ```

#![allow(unknown_lints, clippy::uninlined_format_args)]

mod errors;
pub use crate::errors::*;

pub(crate) mod constants;
pub use crate::constants::*;

mod sequential_cursor;

mod rpm;
pub use crate::rpm::*;

#[cfg(test)]
mod tests;
