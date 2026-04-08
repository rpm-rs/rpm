# AGENTS.md

## What this project is

rpm-rs is a pure Rust library for parsing, creating, and signing RPM packages. It has no dependency on the C librpm — everything is implemented in Rust.

## Sources of truth for the RPM format

The RPM format is defined by its reference C implementation, not by a standalone
specification. When in doubt about format details, consult:

- https://rpm.org — official documentation (may lag behind implementation)
- https://github.com/rpm-software-management/rpm — the C reference implementation

Do not rely on training data for RPM binary format details. The format has subtle
version-dependent behavior (e.g. v4 vs v6 signatures, header region rules) that
is easy to get wrong from memory.

## Building & Testing

```bash
cargo test --all-features        # full test suite
cargo test                       # default features only
cargo clippy --all-features -- -D warnings
cargo fmt --check
```

CI tests the full feature matrix: `--all-features`, `--no-default-features`, across Linux/macOS/Windows. Changes must compile under all combinations.

## Feature flags

New public API that depends on a feature must be gated with `#[cfg(feature = "...")]`. The `signature-pgp` feature implies `signature-meta`. See `Cargo.toml` for the full list.

## Platform-specific code

The builder (`src/rpm/builder.rs`) and parts of `package.rs` are `#[cfg(unix)]`-only. File ownership, permissions, and capabilities are Unix concepts with no Windows equivalent. Tests that exercise these paths will not run on Windows.

## Test organization

Integration tests live in `tests/`, each file covering a different area. New features should get coverage across all relevant test files:

- **`common.rs`** — Shared fixture path constants. Always use these rather than hardcoding paths.
- **`building.rs`** — PackageBuilder API and validation.
- **`parsing.rs`** — Reading metadata back from fixture RPMs.
- **`signatures.rs`** — Signing, verification, digest checking, keyring operations.
- **`payload.rs`** — Extracting and verifying file contents across compression types and format versions.
- **`compare.rs`** — Compares rpm-rs–built packages against reference fixture RPMs to catch format regressions.
- **`compat.rs`** — Runs the system `rpm` tool inside containers to validate real-world compatibility. Requires the `test-with-podman` feature flag.

### Test fixtures

Fixture RPMs and signing keys live in `tests/assets/`, organized by signature version (v4, v6). Check what already exists before creating a new one.

## Changelog & PR conventions

- CHANGELOG.md follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format. Add entries under `## Unreleased` with appropriate subsection (`Added`, `Fixed`, `Changed`, `Removed`).
- Commits should explain WHAT and WHY, and reference issues with "Closes #N".
- Each commit should pass `cargo fmt` and `cargo clippy --all-features -- -D warnings`.
- The project uses semantic versioning.

## Common pitfalls

- **Feature combinations**: Code that compiles with `--all-features` may not compile with `--no-default-features`. Always check both.
- **Binary parsing**: The crate uses `nom` for binary parsing. RPM is a complex binary format with multiple header sections (lead, signature header, main header, payload). Understand the section you're modifying before changing parser code.
- **Signature versions**: RPM v4 and v6 signatures have different tag sets and structures. v6 adds post-quantum algorithm support. Changes to signature handling must account for both versions.
- **`#[non_exhaustive]` on errors**: The `Error` enum is non-exhaustive. New error variants can be added without a major version bump, but downstream match arms must have wildcards.
