//! # rpm-rs
//!
//! A library providing API to parse rpms as well as
//! creating rpms from individual files.
//!
//! # Example
//!
//! ```rust
//!
//! # #[cfg(feature = "signature-meta")]
//! use rpm::{
//!     signature::pgp::{
//!         Signer,
//!         Verifier
//!     }
//! };
//! use std::str::FromStr;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # #[cfg(feature = "signature-meta")]
//! # {
//! let raw_secret_key = std::fs::read("./test_assets/secret_key.asc")?;
//! let pkg = rpm::RPMBuilder::new("test", "1.0.0", "MIT", "x86_64", "some awesome package")
//!             .compression(rpm::Compressor::from_str("gzip")?)
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
//!              .with_file(
//!                 "./test_assets/awesome.toml",
//!                 // you can set a custom mode and custom user too
//!                 rpm::RPMFileOptions::new("/etc/awesome/second.toml")
//!                         .mode(rpm::FileMode::regular(0o644))
//!                         .user("hugo"),
//!             )?
//!             .pre_install_script("echo preinst")
//!             .add_changelog_entry("me", "was awesome, eh?", 123123123)
//!             .add_changelog_entry("you", "yeah, it was", 12312312)
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

#[cfg(feature = "signature-meta")]
mod sequential_cursor;

mod rpm;
pub use crate::rpm::*;

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "test-with-podman"))]
mod compat_tests;
