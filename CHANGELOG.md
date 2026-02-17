# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## 0.19.0

### Changed

- Peak memory should be reduced when building packages as files are now read lazily when being added to the package archive.
- Reduce memory by read file content to writer straight from the archive instead of reading each file entirely into memory before writing them when extract package.

### Breaking Changes

- Bump MSRV to 1.88

### Changed

- Bump `pgp` to `0.18.0`

## 0.18.4

### Added

- Built "v6" packages will set the `RPMFORMAT` tag
- Built "v6" packages will set the `PAYLOADSIZE` and `PAYLOADSIZEALT` tags

### Fixed

- The "v6" `BuildConfig` options were incorrectly failing to use v6 defaults

## 0.18.3

### Fixed

- Packages built with the RPMv4 configuration now populate payload length tags in the signature header. Newly built RPMs will have this set automatically.
  - If editing a pre-built RPM (e.g., for signing) the tag will be preserved if already present.
  - RPMv4 requires the presence of this tag.

### Changed

- Bump `pgp` to `0.17.0`

## 0.18.2

### Changed

- Made the fields of `FileDigest` public

## 0.18.1

### Fixed

- Only set verbatim permissions on unix allowing the crate to build on Windows again.

## 0.18.0

### Added

- Added support for multiple signatures on a package as supported by upstream RPM.
- RPMs that internally use the stripped-cpio format for the archive (v6 RPMs, or older ones with a file
  larger than 4gb) are now supported.
- Added support for Sha3 checksums in headers and payloads - includes the addition of these checksums to
  newly-built packages.
- Added support for Sha512 checksums for payload verification, including addition to new packages.
- Can now use `PackageBuilder::using_config()` to provide a configuration that may be common across many
  package builds.
- `PackageMetadata::get_nevra()`, which is useful for sorting the packages or generating NEVRA strings.

### Fixed

- RPM packages that use large files (>4gb) now correctly declare rpmlib() dependency and use the correct
  archive format.
- RPM "NEVRA" parsing was incorrect in cases where the package name included hyphen ('-') characters.

### Changed

- Internally vendored and modified Jonathan Creekmore's `cpio` dependency, as RPM doesn't use vanilla CPIO.
  See [#108](https://github.com/rpm-rs/rpm/issues/108) or the notes in `src/payload.rs`.
- Switched the `flate2` and `bzip2` dependencies to use native Rust implementations of the underlying compression.
- Added `PackageBuilder::with_file_contents()` for inserting binary content directly into packages instead of requiring on-disk files.
- Bump `pgp` to `0.16.0`
- Bump `bzip2` to `0.6.0`

### Breaking Changes

- Moved `PackageBuilder::compression()` functionality to the new build config via `BuildConfig::compression()`.

## 0.17.0

### Added

- Added support for ecdsa signatures
- Added `Package::files()` for iterating over the files of an RPM package (metadata & contents).
- Added `Package::extract()` for extracting the archive contents of an RPM package to a directory on disk.
- Added `Package::clear_signatures()` for removing signatures from an existing package.

### Changed

- Replaced unmaintained `xz2` dependency with the maintained `liblzma` fork

### Fixed

- Resolved an issue where package signatures produced by this library were not able to be verified on older
  versions of RPM such as the one used on EL8.

### Breaking Changes

- Minimum supported Rust version updated to 1.85 (Edition 2024)

## 0.16.0

### Added

- Added `zstdmt` feature which sets zstd compression to use all available cores.
- Added feature flags for every compression algorithm to support disabling unused ones.
- Added support for signing with a key held in an HSM

### Changed

- Bump `pgp` to 0.14.0

### Breaking Changes

- Changed default compression scheme from Gzip to Zstd.
- Removed bzip2 from the compression options enabled by default.
- Minimum supported Rust version updated to 1.75

## 0.15.1

### Changed

- The `Header::parse_header` function gained a speed up related to parsing of the binary headers.

## 0.15.0

### Breaking Changes

- `FileVerifyFlags` member names changed to strip the `VERIFY_` prefix.
- Minimum supported Rust version updated to 1.74

### Added

- `FileOptions::verify()`
- Added `Evr` and `Nevra` structs and `rpm_evr_compare` function for comparing RPM versions.

### Changed

- As RHEL 7 (thus, CentOS 7 and other derivatives) goes out-of-support on June 30, 2024, support for legacy
  features used by distros of that era are being phased out.
  - "RPM v3" signatures (signatures covering both header and payload) will no longer be added when building
    or signing an RPM with rpm-rs.
  - Legacy checksum types ("sha1" and "md5") will not be added when building an RPM with rpm-rs.
  - As a result of these changes, packages built by rpm-rs will still work on EL7-era distros, but rpm on those
    platforms won't be as capable of verifying them.

### Deprecated

- In a (near) future version of rpm-rs, support for EL7-era distros may be removed entirely.

## 0.14.0

### Breaking Changes

- Minimum supported Rust version updated to 1.71
- `Dependency::rpmlib()` now inserts the `rpmlib()` portion automatically, only the feature name itself should
  be provided in the string passed as the name argument.
- `FileOptions::is_no_replace()` is now `FileOptions::is_config_noreplace()` to reflect the fact that the noreplace
  flag is only applicable to config files, and have more similar usage relative to `%config(noreplace)`

### Added

- `Dependency::script_pre()`, `Dependency::script_post()`, `Dependency::script_preun()`, `Dependency::script_postun()`
- `Dependency::config()`, `Dependency::user()`, `Dependency::group()`
- `PackageBuilder::verify_script()`
- `PackageBuilder::group()` and `PackageBuilder::packager()`
- Added support for the automatic user/group creation feature in rpm 4.19

### Changed

- Improved documentation
- `PackageMetadata::write` is now public

### Fixed

- Using file capabilities now adds the appropriate rpmlib() dependency

## 0.13.1

### Added

- Support bzip2 compression type (`CompressionType::Bzip2`).
- Added `pre_trans_script`, `post_trans_script`, `pre_untrans_script`, and `post_untrans_script` methods to `PackageBuilder`. This corresponds with the `%pretrans`, `%postrans`, `%preuntrans`, and `%postuntrans` scriptlets.
- Added new `Scriptlet` type which enabled configuring scriptlet flags and interpreter settings
  - Example Usage:

  ```rs
  package_builder
    .pre_install_script(
      Scriptlet::new("echo hello world")
        .flags(ScriptletFlags::EXPAND)
        .prog(vec!["/bin/blah/bash", "-c"])
    )
  ```

- Added `get_*_script` methods to `PackageMetadata` for finding scriptlets
  - Example Usage:

  ```rs
  package.metadata.get_pre_install_script()?;
  ```

### Changed

- `Error` now implements `Send + Sync` (therefore, `Result<Package, Error>` now implements `Send + Sync`).
- Add mod `rpm::filecaps` instead of capctl crate - this fixes Windows builds

## 0.13.0

### Breaking Changes

- Bumped MSRV to 1.67

### Removed

- Removed `Package::get_file_checksums` and `Package::get_file_ima_signatures` functions, the same information is now retrievable using `Package::get_file_entries`.

### Added

- Support for symbolic link in file mode.
- Make file type const `REGULAR_FILE_TYPE` `DIR_FILE_TYPE` `SYMBOLIC_LINK_FILE_TYPE` public, because `FileMode::file_type` is public, sometimes we need this const to determine file type.
- Method `PackageBuilder::new` now takes a `summary` as last parameter, instead
  of a `description`. A new method `PackageBuilder::description` can be used to
  set a detailed description for a package; if not set, the description defaults
  to the `summary`.
- Add method `with_key_passphrase` to `signature::pgp::Signer`, to provide the
  passphrase when the PGP secret key is passphrase-protected.
- Add method `is_no_replace` to `FileOptionsBuilder`, used to set the
  `%config(noreplace)` flag on a file.
- Added the `FileEntry.linkto` field that is a target of a symbolic link.
- Function `Package::get_file_entries` returns an empty vector for an RPM package without any files.
- `FileEntry` structs returned by (`Package::get_file_entries`) now include IMA signature information as well as digests for file entries.

## 0.12.1

### Added

- Support for setting file capabilities via the RPMTAGS_FILECAPS header.
- `PackageMetadata::get_file_entries` method can get capability headers for each file.

## 0.12.0

### Breaking Changes

- Removed `RPM` prefix from type names, e.g. `RPMPackage` is renamed to `Package`,
  `RPMBuilder` is renamed to `PackageBuilder`, etc. Many other type names are adjusted
  likewise.
- The `PackageBuilder::build_time` method is removed. Package build time is now
  included by default and can be clamped using the `PackageBuilder::source_date` method.
- Several of the signer and verifier trait APIs were changed

Note: The pace of breaking changes ought to slow down significantly from this point forwards.
Most of the substantial changes which needed to be made have now been made. Thank you for your
patience.

### Added

- `PackageBuilder::source_date` method for clamping modification time of files,
  build time of the package, and signature timestamp. This functionality is required for
  reproducible generation of packages.
- `Package::sign_with_timestamp` method for signing a package while using a specific
  timestamp. This is needed to reproducibly sign packages.
- `PackageMetadata::signature_key_id` method for getting the signing key ID (superset
  of the fingerprint) of the key used to sign a package as a hex-encoded string.
  Key fingerprints can be easily extracted from this value.
- The "rpmversion" tag is now populated so that packages know which library (and version)
  they were built with.
- Support for signing and verification with EdDSA signatures

### Changed

- Build time metadata is now included in the built package by default
- The algorithm type is no longer baked into the Signing and Verifying APIs as it is unnecessary.

### Fixed

- CentOS 7 support by using long sizes only for packages bigger than 4 GiB.
- Avoid a longstanding bug in `rpm --rebuilddb` by adding a package build time by default.
- Packages generated by `RPMBuilder` have the RPMTAG_SOURCERPM to be more compatibly recognized as RPM binary packages.

## 0.11.0

### Breaking Changes

- `CompressionType::None` is now returned instead of an error when calling `get_compression()` on
  a package with an uncompressed payload.
- Moved many constants to the bitflag-like types `DependencyFlags`, `FileVerifyFlags` and `FileFlags`
- Changed the `FileEntry.category` field to `FileEntry.flags` and changed its type from an
  enum to a bitflag-like type.
- Renamed `FileDigestAlgorithm` to `DigestAlgorithm`, renamed `UnsupportedFileDigestAlgorithm`
  to `UnsupportedDigestAlgorithm`

### Added

- The compression level to be used during package building is now configurable by passing
  `CompressionWithLevel` to `RPMBuilder::compression`. Compatibility with passing
  `CompressionType` is retained - the default value will be used in that case.
- The default compression for building a package, if the compression is not overridden using
  the above method, is now `Gzip` rather than `None`. This is chosen to keep package
  sizes reasonable while maintaining maximum compatibility and minimizing computational cost.
- Exposed `RPMPackageMetadata::parse()` and `RPMPackageMetadata::open()` so that it is
  possible to read only package metadata without loading the payload into memory. This saves
  time and memory over reading the entire file.
- Exposed the fields on the `Dependency` and `RPMFileEntry` structs.

### Removed

- Removed async support. This crate is poorly suited for use in an async runtime as IO is intermixed
  with computationally expensive compression/decompression, digest and signature verification which
  is likely to take on the order of seconds in some cases. This is "computational blocking". As an
  alternative, if you need to perform actions with this crate within an async runtime, use the
  `spawn_blocking` function on your executor of choice e.g.
  <https://docs.rs/tokio/latest/tokio/index.html#cpu-bound-tasks-and-blocking-code>

### Changed

- `flate2` crate is now used in place of `libflate`. `flate2` is faster in both compression
  and decompression and has better ratios, and includes features which `libflate` does not
  such as configurable compression levels.

### Fixed

- Made parsing more robust in the face of unknown or unexpected tags. This will prevent new
  packages from causing the program to crash if rpm-rs does not yet have a constant defined.
  Also, RPMs in the wild are "messy" and it is sadly commonplace for tags to present in the
  wrong header.

## 0.10.0

### Added

- Added a `RPMPackage::open()` helper for working with files
- Set RPMTAG_ENCODING to "utf-8" on all built RPMs
- Added `$pkg.metadata.get_changelog_entries()`
- Added the following functions to `RPMBuilder` to support weak dependencies: `recommends()`,
  `suggests()`, `enhances()` and `supplements()`
- Added the following additional functions to `RPMBuilder`: `cookie()`, `build_host()`
- Added the following functions to `$pkg.metadata` for retrieval of various kinds of RPM
  dependencies: `get_provides()`, `get_requires()`, `get_obsoletes()`, `get_conflicts()`,
  `get_recommends()`, `get_suggests()`, `get_enhances()`, `get_supplements()`
- Added the following functions to `$pkg.metadata` for retrieval of metadata: `get_group()`,
  `get_description()`, `get_summary()`
- Added the following functions to `$pkg.metadata.header` to enable the reading of arbitrary
  tags in the header: `get_entry_data_as_binary()`, `get_entry_data_as_string()`,
  `get_entry_data_as_u16_array()`, `get_entry_data_as_u32()`, `get_entry_data_as_u32_array()`,
  `get_entry_data_as_u64()`, `get_entry_data_as_u64_array()`, `get_entry_data_as_string_array()`,
  `get_entry_data_as_i18n_string()`
- Added `verify_signature()` and `verify_digests()` to `RPMPackage` to enable checking the integrity
  and provenance of packages.
- Added `get_package_segment_boundaries()` to `RPMPackage` to enable reading the raw bytes of the
  different components (header, payload, etc.) from an on-disk package.
- Added `CompressionType`.
- Added support for `xz` compression type
- Write a sha256 header digest to the signature header as the more modern equivalent of the sha1
  header digest

### Fixed

- Added `rpmlib()` dependencies to built packages as appropriate
- Fixed an issue where `get_file_paths()` and `get_file_entries()` would fail if the package
  did not have any files associated.
- Ensured that digests are always added to built RPMs. Previously they would not be included unless
  the "signature-meta" (or "signature-pgp") features were enabled.
- Added `PAYLOADDIGEST`, `PAYLOADDIGESTALT`, and `PAYLOADDIGESTALGO` tags to built packages.
- To facilitate reproducible builds, stop writing `build_time` to the package by default.
  Users can configure it with `RPMBuilder::build_time()`.
- Improved support for packages >4gb
- Always write tags in sorted order

### Breaking Changes

- Bump MSRV to 1.65.0
- Removed async support from default features
- Removed `Lead` from the public API. `Lead` is long-deprecated and shouldn't be relied on.
  Restricted the data we write to `Lead` to the bare minimum required for compatibility.
- Removed `$pkg.metadata.get_payload_format()`. It is still possible to fetch manually, but
  practically speaking it is not meaningful. rpmbuild has written a misleading value here for
  10 years.
- Added support for parsing `CompressionType` string in `RPMPackageMetadata`.
- Changed signature for `RPMBuilder::compression`.

## 0.9.0

### Breaking Changes

- Bump MSRV to 1.60.0
- Changed a couple of APIs to use unsigned integers instead of signed integers where appropriate
- Moved pre-defined helpers for common package metadata (such as name, version, file lists, etc.)
  from `$pkg.metadata.header` to `$pkg.metadata`
- Removed the `$pkg.metadata.get_file_ima_signature_length()` function

### Added

- Forked from `rpm-rs` at version 0.8.1
- Relicensed as MIT + Apache 2.0 after obtaining consent from all contributors
- Added additional helper methods for retrieving commonly used metadata
- Add vendor, url and vcs metadata optional fields to RPMBuilder

### Fixed

- Updated dependencies to latest versions
- Fix up most issues when compiling with --no-default-features.
- Fixed an issue with improper package signing

[Unreleased]: https://github.com/rpm-rs/rpm-rs/compare/vTODO...HEAD
