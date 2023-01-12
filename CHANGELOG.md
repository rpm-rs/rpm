# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
