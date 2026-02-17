[![crates.io](https://img.shields.io/crates/v/rpm.svg)](https://crates.io/crates/rpm)
[![docs.rs](https://docs.rs/rpm/badge.svg)](https://docs.rs/rpm)
[![MSRV](https://img.shields.io/badge/rustc-1.88.0+-ab6000.svg)](https://blog.rust-lang.org/2025/06/26/Rust-1.88.0/)

## RPM-RS

A pure rust library for parsing and creating RPM files.

### Goals

- Easy to use API
- Pure rust to make it easy to use in larger Projects
- Independence of Spec files. Pure programmatic interface for Packaging.
- Compatibility from Enterprise Linux 8 (RHEL, Alma, Rocky, CentOS Stream) to Fedora (I may extend test cases for SUSE)

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

### Read package and access metadata

```rust
use rpm::signature::pgp::{Signer, Verifier};

let pkg = rpm::Package::open("test_assets/389-ds-base-devel-1.3.8.4-15.el7.x86_64.rpm")?;

let name = pkg.metadata.get_name()?;
let version = pkg.metadata.get_version()?;
let release = pkg.metadata.get_release()?;
let arch = pkg.metadata.get_arch()?;

println!("{}-{}-{}.{}", name, version, release, arch);

for changelog in pkg.metadata.get_changelog_entries()? {
    println!("{}\n{}\n", changelog.name, changelog.description);
}
```

#### Sign existing package and verify package signature

```rust
use rpm::signature::pgp::{Signer, Verifier};

let raw_secret_key = std::fs::read("./test_assets/secret_key.asc")?;
let raw_pub_key = std::fs::read("/path/to/gpg.key.pub")?;

let mut pkg = rpm::Package::open("test_assets/389-ds-base-devel-1.3.8.4-15.el7.x86_64.rpm")?;
pkg.sign(&raw_secret_key)?;
pkg.write_file("./with_signature.rpm")?;

let pkg = rpm::Package::open("./with_signature.rpm")?;
pkg.verify_signature(Verifier::load_from_asc_bytes(&raw_pub_key)?)?;
```

#### Build new package

```rust
use rpm::signature::pgp::Signer;

let build_config = rpm::BuildConfig::default().compression(rpm::CompressionType::Gzip);

let raw_secret_key = std::fs::read("./test_assets/secret_key.asc")?;
// It's recommended to use timestamp of last commit in your VCS
let source_date = 1_600_000_000;
let pkg = rpm::PackageBuilder::new("test", "1.0.0", "MIT", "x86_64", "some awesome package")
    .using_config(build_config)
    .with_file(
        "./test_assets/awesome.toml",
        rpm::FileOptions::new("/etc/awesome/config.toml")
            .is_config()
            .is_no_replace(),
    )?
    // file mode is inherited from source file
    .with_file(
        "./test_assets/awesome.py",
        rpm::FileOptions::new("/usr/bin/awesome"),
    )?
    .with_file(
        "./test_assets/awesome.toml",
        // you can set a custom mode and custom user too
        rpm::FileOptions::new("/etc/awesome/second.toml")
            .mode(rpm::FileMode::regular(0o644))
            .caps("cap_sys_admin,cap_net_admin=pe")?
            .user("hugo"),
    )?
    .pre_install_script("echo preinst")
    // Alternatively, use scriptlet builder api to specify flags and interpreter/arguments
    .post_trans_script(
        Scriptlet::new("echo posttrans")
            .flags(ScriptletFlags::EXPAND)
            .prog(vec!["/bin/blah/bash", "-c"])
    )
    // If you don't need reproducible builds,
    // you can remove the following line
    .source_date(source_date)
    .build_host(gethostname::gethostname().to_str().unwrap_or("host"))
    .add_changelog_entry(
        "Max Mustermann <max@example.com> - 0.1-29",
        "- was awesome, eh?",
        chrono::DateTime::parse_from_rfc2822("Wed, 19 Apr 2023 23:16:09 GMT")
            .expect("Date 1 is correct. qed"),
    )
    .add_changelog_entry(
        "Charlie Yom <test2@example.com> - 0.1-28",
        "- yeah, it was",
        // Raw timestamp for 1996-08-14 05:20:00
        840_000_000,
    )
    .requires(rpm::Dependency::any("wget"))
    .vendor("corporation or individual")
    .url("www.github.com/repo")
    .vcs("git:repo=example_repo:branch=example_branch:sha=example_sha")
    .build_and_sign(Signer::load_from_asc_bytes(&raw_secret_key)?)?;

pkg.write_file("./awesome.rpm")?;
```
