## RPM-RS

A pure rust library for parsing and creating RPM files.

### Goals

- Easy to use API
- Pure rust to make it easy to use in larger Projects
- Independence of Spec files. Pure programmatic interface for Packaging.
- Compatibility  to Centos 7 / Fedora (I may extend test cases for SUSE)

### Non Goals

RPM has a lot of cryptic features. I do not want to re-implement all of them. This library focuses on
the ones that I assume as useful.
This library does not build software like rpmbuild. It is meant for finished artifacts that need to be packaged as RPM.

### Status

- [x] RPM Creation
- [x] Basic RPM Reading
- [x] RPM Signing and Signature Verification
- [ ] High Level API for RPM Reading



### Examples

```rust
use rpm;
use rpm::signature::pgp::{Signer,Verifier};

let raw_secret_key = std::fs::read("/path/to/gpg.secret.key")?;
let pkg = rpm::RPMBuilder::new("test", "1.0.0", "MIT", "x86_64", "some awesome package")
            .compression(rpm::Compressor::from_str("gzip")?)
            .with_file(
                "./awesome-config.toml",
                RPMFileOptions::new("/etc/awesome/config.toml").is_config(),
            )?
            // file mode is inherited from source file
            .with_file(
                "./awesome-bin",
                RPMFileOptions::new("/usr/bin/awesome"),
            )?
             .with_file(
                "./awesome-config.toml",
                // you can set a custom mode and custom user too
                RPMFileOptions::new("/etc/awesome/second.toml").mode(0o100744).user("hugo"),
            )?
            .pre_install_script("echo preinst")
            .add_changelog_entry("me", "was awesome, eh?", 123123123)
            .add_changelog_entry("you", "yeah, it was", 12312312)
            .requires(Dependency::any("wget"))
            .build_and_sign(Signer::load_from_asc_bytes(&raw_secret_key)?)
let mut f = std::fs::File::create("./awesome.rpm")?;
pkg.write(&mut f)?;

// reading
let raw_pub_key = std::fs::read("/path/to/gpg.key.pub")?;
let rpm_file = std::fs::File::open("test_assets/389-ds-base-devel-1.3.8.4-15.el7.x86_64.rpm")?;
let mut buf_reader = std::io::BufReader::new(rpm_file);
let pkg = rpm::RPMPackage::parse(&mut buf_reader)?;
// verifying
pkg.verify_signature(Verifier::load_from_asc_bytes(&raw_pub_key)?)?;
```
