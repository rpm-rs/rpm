# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added a `RPMPackage::open()` helper for working with files
- Set RPMTAG_ENCODING to "utf-8" on all built RPMs
- Added `$pkg.metadata.get_changelog_entries()`
- Added the following functions to `RPMBuilder` to support weak dependencies: `recommends()`,
  `suggests()`, `enhances()` and `supplements()`
- Added the following additional functions to `RPMBuilder`: `cookie()`, `build_host()`
- Added `get_build_cookie()` for use with `RPMBuilder::cookie()`
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
- Support the `SOURCE_DATE_EPOCH` environment variable for overriding the timestamp during package
  builds (for reproducable builds), as well as allow it to be manually overridden with `build_time()`

### Fixed

- Added `rpmlib()` dependencies to built packages as appropriate
- Fixed an issue where `get_file_paths()` and `get_file_entries()` would fail if the package
  did not have any files associated.
- Ensured that digests are always added to built RPMs. Previously they would not be included unless
  the "signature-meta" (or "signature-pgp") features were enabled.

### Breaking Changes

- Bump MSRV to 1.64.0
- Removed async support from default features
- Removed `Lead` from the public API. `Lead` is long-deprecated and shouldn't be relied on.
  Restricted the data we write to `Lead` to the bare minimum required for compatibility.
- Removed `$pkg.metadata.get_payload_format()`. It is still possible to fetch manually, but
  practically speaking it is not meaningful. rpmbuild has written a misleading value here for
  10 years.

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
