# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

### Changed

- `flate2` crate is now used in place of `libflate`. `flate2` is faster in both compression
  and decompression and has better ratios, and includes features which `libflate` does not
  such as configurable compression levels.
- Moved many constants to the bitflag-like types `DependencyFlags`, `FileVerifyFlags` and `FileFlags`
- Changed the `FileEntry.category` field to `FileEntry.flags` and changed its type from an
  enum to a bitflag-like type.
- Renamed `FileDigestAlgorithm` to `DigestAlgorithm`, renamed `UnsupportedFileDigestAlgorithm`
  to `UnsupportedDigestAlgorithm`

### Fixed

- Made parsing more robust in the face of unknown or unexpected tags. This will prevent new
  packages from causing the program to crash if rpm-rs does not yet have a constant defined.
  Also, RPMs in the wild are "messy" and it is sadly commonplace for tags to present in the
  wrong header.

### Removed

- Removed async support. This crate is poorly suited for use in an async runtime as IO is intermixed
  with computationally expensive compression/decompression, digest and signature verification which
  is likely to take on the order of seconds in some cases. This is "computational blocking". As an
  alternative, if you need to perform actions with this crate within an async runtime, use the
  `spawn_blocking` function on your executor of choice e.g.
  <https://docs.rs/tokio/latest/tokio/index.html#cpu-bound-tasks-and-blocking-code>

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
