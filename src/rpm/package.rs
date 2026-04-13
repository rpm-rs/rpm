use std::{
    borrow::Cow,
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    str::FromStr,
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use digest::Digest;
use num_traits::FromPrimitive;

use crate::{CompressionType, Nevra, constants::*, decompress_stream, errors::*};

#[cfg(feature = "signature-pgp")]
use crate::signature::pgp::Verifier;
#[cfg(feature = "signature-meta")]
use crate::{Timestamp, signature};
#[cfg(feature = "signature-meta")]
use std::fmt::Debug;

use super::Lead;
use super::headers::*;
use super::payload;

#[cfg(unix)]
fn symlink(original: impl AsRef<Path>, link: impl AsRef<Path>) -> Result<(), Error> {
    std::os::unix::fs::symlink(original, link)?;
    Ok(())
}

#[cfg(windows)]
fn symlink(original: impl AsRef<Path>, link: impl AsRef<Path>) -> Result<(), Error> {
    let original = original.as_ref();

    let Ok(metadata) = original.metadata() else {
        // Windows symlink creation requires the target to exist and be accessible.
        // Relative symlinks (e.g., "../dir") or targets outside the extraction directory
        // will fail, so we silently skip them to allow extraction to continue.
        // This matches RPM's behavior where symlinks are informational metadata.
        return Ok(());
    };

    if metadata.is_dir() {
        std::os::windows::fs::symlink_dir(original, link)?;
    } else {
        std::os::windows::fs::symlink_file(original, link)?;
    }

    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn symlink(_original: &Path, _link: &Path) -> Result<(), Error> {
    Err(Error::UnsupportedSymlink)
}

/// The result of checking a single digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DigestStatus {
    /// The digest was present and matches the computed value.
    Verified,
    /// The digest tag was not present in the package headers.
    NotPresent,
    /// The digest was not checked (e.g. payload digests when only metadata is available).
    NotChecked,
    /// The digest was present but did not match the computed value.
    Mismatch {
        /// The value declared in the RPM header.
        expected: String,
        /// The value computed from the actual content.
        actual: String,
    },
}

impl DigestStatus {
    /// Returns `true` if this digest was present and verified.
    pub fn is_verified(&self) -> bool {
        matches!(self, DigestStatus::Verified)
    }

    /// Returns `true` if this digest tag was not present.
    pub fn is_not_present(&self) -> bool {
        matches!(self, DigestStatus::NotPresent)
    }

    /// Returns `true` if this digest was not checked.
    pub fn is_not_checked(&self) -> bool {
        matches!(self, DigestStatus::NotChecked)
    }

    /// Returns `true` if this digest was present but mismatched.
    pub fn is_mismatch(&self) -> bool {
        matches!(self, DigestStatus::Mismatch { .. })
    }

    /// Check a digest by comparing the expected value (from a header lookup)
    /// against the actual hash of the provided data.
    ///
    /// If the lookup returned an error (tag not present), returns `NotPresent`.
    fn check_digest_against_tag<D: Digest>(expected: Result<&str, Error>, data: &[u8]) -> Self {
        match expected {
            Ok(expected) => {
                let actual = hex::encode(D::digest(data));
                if expected == actual {
                    DigestStatus::Verified
                } else {
                    DigestStatus::Mismatch {
                        expected: expected.to_string(),
                        actual,
                    }
                }
            }
            Err(_) => DigestStatus::NotPresent,
        }
    }
}

/// Results of verifying all digests in the package.
///
/// Each field represents a specific digest type. Not all digests are present
/// in all packages — v4 packages typically have MD5, SHA1, and SHA256, while
/// v6 packages add SHA3-256 and SHA-512 variants.
#[derive(Debug, Clone)]
pub struct DigestReport {
    /// SHA-1 of the header (signature header, v4 packages).
    pub sha1_header: DigestStatus,
    /// SHA-256 of the header (signature header).
    pub sha256_header: DigestStatus,
    /// SHA3-256 of the header (signature header, v6 packages).
    pub sha3_256_header: DigestStatus,
    /// SHA-256 of the compressed payload.
    pub payload_sha256: DigestStatus,
    /// SHA-512 of the compressed payload (v6 packages).
    pub payload_sha512: DigestStatus,
    /// SHA3-256 of the compressed payload (v6 packages).
    pub payload_sha3_256: DigestStatus,
}

impl DigestReport {
    /// Returns `true` if at least one header digest was present.
    pub fn has_header_digest(&self) -> bool {
        !self.sha1_header.is_not_present()
            || !self.sha256_header.is_not_present()
            || !self.sha3_256_header.is_not_present()
    }

    /// Returns `true` if at least one payload digest was present.
    pub fn has_payload_digest(&self) -> bool {
        !self.payload_sha256.is_not_present()
            || !self.payload_sha512.is_not_present()
            || !self.payload_sha3_256.is_not_present()
    }

    /// Collapse into a `Result`: fails if any digest mismatched or if no
    /// header digests are present at all.
    ///
    /// Digests that are [`DigestStatus::NotPresent`] are **not** individually
    /// considered failures, but at least one header digest must be present.
    pub fn result(&self) -> Result<(), Error> {
        let all = [
            ("header SHA1", &self.sha1_header),
            ("header SHA-256", &self.sha256_header),
            ("header SHA3-256", &self.sha3_256_header),
            ("payload SHA-256", &self.payload_sha256),
            ("payload SHA-512", &self.payload_sha512),
            ("payload SHA3-256", &self.payload_sha3_256),
        ];
        for (label, status) in all {
            if let DigestStatus::Mismatch { expected, actual } = status {
                return Err(Error::DigestMismatchError {
                    digest: label,
                    expected: expected.clone(),
                    actual: actual.clone(),
                });
            }
        }
        Ok(())
    }

    /// Returns `true` if every present digest verified and none mismatched.
    pub fn is_ok(&self) -> bool {
        self.result().is_ok()
    }
}

/// The result of verifying a single signature against the provided keys.
#[cfg(feature = "signature-pgp")]
#[derive(Debug)]
pub struct SignatureCheckResult {
    /// Parsed metadata about the signature (fingerprint, algorithm, etc.).
    pub info: signature::pgp::SignatureInfo,
    /// `None` if verified successfully, `Some(error)` if verification failed.
    pub error: Option<Error>,
}

#[cfg(feature = "signature-pgp")]
impl SignatureCheckResult {
    /// Returns `Ok(())` if verified, or `Err` with the verification error.
    pub fn result(&self) -> Result<(), &Error> {
        match &self.error {
            None => Ok(()),
            Some(e) => Err(e),
        }
    }

    /// Returns `true` if this signature was successfully verified.
    pub fn is_verified(&self) -> bool {
        self.error.is_none()
    }
}

/// Results of verifying all digests and signatures in the package.
#[cfg(feature = "signature-pgp")]
#[derive(Debug)]
pub struct SignatureReport {
    /// Digest verification results.
    pub digests: DigestReport,
    /// Per-signature verification results, in the order they appear in the package.
    pub signatures: Vec<SignatureCheckResult>,
}

#[cfg(feature = "signature-pgp")]
impl SignatureReport {
    /// Collapse into a `Result`: fails if any digest mismatched or if no signature
    /// was successfully verified.
    ///
    /// When no signature verified, the error from the last failed attempt is returned
    /// (preserving the original error type).
    pub fn into_result(self) -> Result<(), Error> {
        self.digests.result()?;
        let mut last_err = None;
        for sig in self.signatures {
            if sig.is_verified() {
                return Ok(());
            }
            last_err = sig.error;
        }
        Err(last_err.unwrap_or(Error::NoSignatureFound))
    }

    /// Returns `true` if digests are ok and at least one signature verified.
    pub fn is_ok(&self) -> bool {
        self.digests.is_ok() && self.signatures.iter().any(|s| s.is_verified())
    }
}

/// A complete rpm file.
///
/// Can either be created using the [`PackageBuilder`](crate::PackageBuilder)
/// or used with [`parse`](`self::Package::parse`) to obtain from a file.
#[derive(Clone, Debug)]
pub struct Package {
    /// Header and metadata structures.
    ///
    /// Contains the constant lead as well as the metadata store.
    pub metadata: PackageMetadata,
    /// The compressed or uncompressed files.
    pub content: Vec<u8>,
}

impl Package {
    /// Open and parse a file at the provided path as an RPM package
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let rpm_file = fs::File::open(path.as_ref())?;
        let mut buf_reader = io::BufReader::new(rpm_file);
        Self::parse(&mut buf_reader)
    }

    /// Parse an RPM package from an existing buffer
    pub fn parse(input: &mut impl io::BufRead) -> Result<Self, Error> {
        let metadata = PackageMetadata::parse(input)?;
        let mut content = Vec::new();
        input.read_to_end(&mut content)?;
        Ok(Package { metadata, content })
    }

    /// Write the RPM package to a buffer
    pub fn write(&self, out: &mut impl io::Write) -> Result<(), Error> {
        self.metadata.write(out)?;
        out.write_all(&self.content)?;
        Ok(())
    }

    /// Write the RPM package to a file
    pub fn write_file(&self, path: impl AsRef<Path>) -> Result<(), Error> {
        self.write(&mut io::BufWriter::new(fs::File::create(path)?))
    }

    /// Write the RPM package to a file or directory
    ///
    /// If `path` is an existing directory, the package will be written with an auto-generated
    /// filename based on the package NEVRA (name-version-release.arch.rpm).
    /// Otherwise, `path` is treated as a file path (ensuring it has a .rpm extension).
    ///
    /// Returns the actual path where the package was written.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "test").build()?;
    ///
    /// // Write to a directory with auto-generated name
    /// let path = pkg.write_to("/tmp")?;
    /// // Creates: /tmp/foo-1.0.0-1.x86_64.rpm
    ///
    /// // Write to a specific file
    /// let path = pkg.write_to("/tmp/custom-name.rpm")?;
    /// // Creates: /tmp/custom-name.rpm
    /// # Ok(())
    /// # }
    /// ```
    pub fn write_to(&self, path: impl AsRef<Path>) -> Result<PathBuf, Error> {
        let path = path.as_ref();
        let filename = format!("{}.rpm", self.metadata.get_nevra()?.nvra());

        let output_path = if fs::metadata(path).is_ok_and(|m| m.is_dir()) {
            path.join(filename)
        } else {
            path.with_extension("rpm")
        };

        self.write_file(&output_path)?;
        Ok(output_path)
    }

    /// Iterate over the file contents of the package payload
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let package = rpm::Package::open("tests/assets/RPMS/v4/rpm-basic-2.3.4-5.el9.noarch.rpm")?;
    /// for entry in package.files()? {
    ///     let file = entry?;
    ///     // do something with file.content
    ///     println!("{} is {} bytes", file.metadata.path.display(), file.content.len());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn files(&self) -> Result<FileIterator<'_>, Error> {
        let file_entries = self.metadata.get_file_entries()?;
        let archive = decompress_stream(
            self.metadata.get_payload_compressor()?,
            io::Cursor::new(&self.content),
        )?;

        Ok(FileIterator {
            file_entries,
            archive,
            count: 0,
        })
    }

    /// Extract all contents of the package payload to a given directory.
    ///
    /// # Implementation
    ///
    /// The if the directory is nested, its parent directories must already exist. If the
    /// directory itself already exists, the operation will fail. All extracted files will be
    /// dropped relative to the provided directory (it will not install any files).
    ///
    /// ## Platform-specific behavior
    ///
    /// **Windows**: Symbolic links are only created if their target exists at extraction time.
    /// Symlinks with relative targets (e.g., `../dir`) or targets outside the extraction
    /// directory will be silently skipped. This is because Windows symlink creation requires
    /// the target to exist and be accessible.
    ///
    /// **Unix**: All symbolic links are created regardless of whether their target exists.
    ///
    /// # Examples
    ///
    /// ```text
    /// let package = rpm::Package::open("tests/assets/RPMS/v4/rpm-basic-2.3.4-5.el9.noarch.rpm")?;
    /// package.extract(&package.metadata.get_name()?)?;
    /// ```
    pub fn extract(&self, dest: impl AsRef<Path>) -> Result<(), Error> {
        fs::create_dir(&dest)?;

        let dirs = self
            .metadata
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_DIRNAMES)?;

        // pull every base directory name in the package and create the directory in advance
        for dir in &dirs {
            let dir_path = dest
                .as_ref()
                .join(Path::new(dir).strip_prefix("/").unwrap_or(dest.as_ref()));
            fs::create_dir_all(&dir_path)?;
        }

        let mut archive = decompress_stream(
            self.metadata.get_payload_compressor()?,
            io::Cursor::new(&self.content),
        )?;
        let file_entries = self.metadata.get_file_entries()?;

        for file_entry in file_entries.iter() {
            // Ghost files are not present in the payload archive and should not be created
            if file_entry.flags.contains(FileFlags::GHOST) {
                continue;
            }

            let mut entry_reader = payload::Reader::new(&mut archive, &file_entries)?;
            if entry_reader.is_trailer() {
                return Ok(());
            }
            let file_path = dest
                .as_ref()
                .join(file_entry.path.strip_prefix("/").unwrap_or(dest.as_ref()));
            match file_entry.mode.file_type() {
                FileType::Dir => {
                    fs::create_dir_all(&file_path)?;
                    #[cfg(unix)]
                    {
                        let perms =
                            fs::Permissions::from_mode(file_entry.mode.permissions().into());
                        fs::set_permissions(&file_path, perms)?;
                    }
                }
                FileType::Regular => {
                    let mut f = fs::File::create(&file_path)?;
                    io::copy(&mut entry_reader, &mut f)?;
                    #[cfg(unix)]
                    {
                        let perms =
                            fs::Permissions::from_mode(file_entry.mode.permissions().into());
                        f.set_permissions(perms)?;
                    }
                }
                FileType::SymbolicLink => {
                    // broken symlinks (common for debuginfo handling) are perceived as not existing by "exists()"
                    if file_path.exists() || file_path.symlink_metadata().is_ok() {
                        fs::remove_file(&file_path)?;
                    }
                    symlink(&file_entry.linkto, &file_path)?;
                }
                // Skip file types we don't handle (e.g. device nodes, FIFOs, sockets)
                _ => {}
            }
            entry_reader.finish()?;
        }

        Ok(())
    }

    /// Generate a fresh, unsigned signature header
    #[cfg(feature = "signature-meta")]
    pub fn clear_signatures(&mut self) -> Result<(), Error> {
        // create a temporary byte repr of the header
        let mut header_bytes = Vec::<u8>::with_capacity(1024);
        self.metadata.header.write(&mut header_bytes)?;

        self.metadata.signature = SignatureHeaderBuilder::from_existing(&self.metadata.signature)?
            .clear_signatures()
            .calculate_digests(&header_bytes)
            .build()?;

        Ok(())
    }

    /// Create package signatures using an external key and add them to the signature header
    #[cfg(feature = "signature-meta")]
    pub fn sign<S>(&mut self, signer: S) -> Result<(), Error>
    where
        S: signature::Signing<Signature = Vec<u8>>,
    {
        self.sign_with_timestamp(signer, Timestamp::now())
    }

    /// Create package signatures using an external key and provided timestamp.
    /// Adds generated signatures to the signature header.
    ///
    /// This method is usually used for reproducible builds, otherwise you should
    /// prefer using the [`sign`][Package::sign] method instead.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut package = rpm::Package::open("tests/assets/RPMS/v4/rpm-basic-2.3.4-5.el9.noarch.rpm")?;
    /// let raw_secret_key = std::fs::read("./tests/assets/signing_keys/v4/rpm-testkey-v4-rsa4096.secret")?;
    /// let signer = rpm::signature::pgp::Signer::from_asc_bytes(&raw_secret_key)?;
    /// // It's recommended to use timestamp of last commit in your VCS
    /// let source_date = 1_600_000_000;
    /// package.sign_with_timestamp(signer, source_date)?;
    /// # Ok(()) }
    /// ```
    #[cfg(feature = "signature-meta")]
    pub fn sign_with_timestamp<S>(
        &mut self,
        signer: S,
        t: impl TryInto<Timestamp, Error = impl Debug>,
    ) -> Result<(), Error>
    where
        S: signature::Signing<Signature = Vec<u8>>,
    {
        let t = t.try_into().unwrap();
        // create a temporary byte repr of the header
        let mut header_bytes = Vec::<u8>::with_capacity(1024);
        self.metadata.header.write(&mut header_bytes)?;

        let header_signature = signer.sign(header_bytes.as_slice(), t)?;
        let sig_header = SignatureHeaderBuilder::from_existing(&self.metadata.signature)?
            .calculate_digests(&header_bytes)
            .add_openpgp_signature(header_signature)
            .build()?;

        self.metadata.signature = sig_header;
        Ok(())
    }

    /// Return parsed information about each OpenPGP header signature in the package.
    ///
    /// Delegates to [`PackageMetadata::signatures`].
    #[cfg(feature = "signature-pgp")]
    pub fn signatures(&self) -> Result<Vec<signature::pgp::SignatureInfo>, Error> {
        self.metadata.signatures()
    }

    /// Return the raw bytes of each signature in the package's signature header.
    ///
    /// Delegates to [`PackageMetadata::raw_signatures`].
    pub fn raw_signatures(&self) -> Result<Vec<Cow<'_, [u8]>>, Error> {
        self.metadata.raw_signatures()
    }

    /// Verify header-only signatures.
    ///
    /// Legacy v3 signatures that cover the payload are not checked.
    ///
    /// This is a convenience wrapper around [`check_signatures`](Self::check_signatures)
    /// that collapses the detailed report into a pass/fail `Result`.
    #[cfg(feature = "signature-meta")]
    pub fn verify_signature<V>(&self, verifier: V) -> Result<(), Error>
    where
        V: signature::Verifying<Signature = Vec<u8>>,
    {
        self.check_signatures(verifier)?.into_result()
    }

    /// Verify any digests which may be present in the RPM headers.
    ///
    /// This is a convenience wrapper around [`check_digests`](Self::check_digests)
    /// that collapses the detailed report into a pass/fail `Result`.
    pub fn verify_digests(&self) -> Result<(), Error> {
        let digests = self.check_digests()?;

        if !digests.has_header_digest() {
            return Err(Error::NoHeaderDigestError);
        }

        // payload digest existence could be checked here, but since it only started to exist
        // in 2017, it would be a bit much to assume that it will exist and fail otherwise.

        digests.result()
    }

    /// Check all digests in the package and return a detailed report.
    ///
    /// Each digest type is individually checked and its status recorded.
    /// Use [`DigestReport::result`] to collapse into a pass/fail `Result`,
    /// or inspect individual fields for detailed information.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let pkg = rpm::Package::open("my-package.rpm")?;
    /// let report = pkg.check_digests()?;
    ///
    /// // Quick pass/fail
    /// report.result()?;
    ///
    /// // Or inspect individual digests
    /// if report.sha256_header.is_verified() {
    ///     println!("SHA-256 header digest: OK");
    /// }
    /// match &report.sha3_256_header {
    ///     rpm::DigestStatus::Verified => println!("SHA3-256 header digest: OK"),
    ///     rpm::DigestStatus::NotPresent => println!("SHA3-256 header digest: not present"),
    ///     rpm::DigestStatus::NotChecked => println!("SHA3-256 header digest: not checked"),
    ///     rpm::DigestStatus::Mismatch { expected, actual } => {
    ///         println!("SHA3-256 header digest: MISMATCH (expected {expected}, got {actual})");
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn check_digests(&self) -> Result<DigestReport, Error> {
        // --- Header digests (from sig header) ---

        let mut report = self.metadata.check_digests()?;

        // --- Payload digests (from main header) ---

        report.payload_sha256 = DigestStatus::check_digest_against_tag::<sha2::Sha256>(
            self.metadata
                .header
                .get_entry_data_as_string(IndexTag::RPMTAG_PAYLOADSHA256),
            self.content.as_slice(),
        );

        report.payload_sha512 = DigestStatus::check_digest_against_tag::<sha2::Sha512>(
            self.metadata
                .header
                .get_entry_data_as_string(IndexTag::RPMTAG_PAYLOAD_SHA512),
            self.content.as_slice(),
        );

        report.payload_sha3_256 = DigestStatus::check_digest_against_tag::<sha3::Sha3_256>(
            self.metadata
                .header
                .get_entry_data_as_string(IndexTag::RPMTAG_PAYLOAD_SHA3_256),
            self.content.as_slice(),
        );

        Ok(report)
    }

    /// Check all digests and verify all signatures, returning a detailed report.
    ///
    /// Each digest is individually checked, and each signature in the package
    /// is verified against the provided `verifier`. Use [`SignatureReport::into_result`]
    /// to collapse into a pass/fail `Result`, or inspect individual fields.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use rpm::signature::pgp::Verifier;
    ///
    /// let pkg = rpm::Package::open("my-package.rpm")?;
    /// let verifier = Verifier::from_asc_bytes(b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...")?;
    /// let report = pkg.check_signatures(&verifier)?;
    ///
    /// // Quick pass/fail
    /// report.into_result()?;
    ///
    /// // Or inspect individual signatures
    /// let report = pkg.check_signatures(&verifier)?;
    /// for sig in &report.signatures {
    ///     let key_ref = sig.info.fingerprint()
    ///         .or(sig.info.key_id())
    ///         .unwrap_or("unknown");
    ///     match sig.result() {
    ///         Ok(()) => println!("Signature {key_ref}: OK"),
    ///         Err(err) => println!("Signature {key_ref}: FAILED: {err}"),
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "signature-pgp")]
    pub fn check_signatures<V>(&self, verifier: V) -> Result<SignatureReport, Error>
    where
        V: signature::Verifying<Signature = Vec<u8>>,
    {
        let mut report = self.metadata.check_signatures(&verifier)?;
        report.digests = self.check_digests()?;

        Ok(report)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PackageMetadata {
    pub lead: Lead,
    pub signature: Header<IndexSignatureTag>,
    pub header: Header<IndexTag>,
}

impl PackageMetadata {
    /// Open and parse PackageMetadata from the file at the provided path
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let rpm_file = fs::File::open(path.as_ref())?;
        let mut buf_reader = io::BufReader::new(rpm_file);
        Self::parse(&mut buf_reader)
    }

    /// Parse PackageMetadata from the provided reader
    pub fn parse(input: &mut impl io::BufRead) -> Result<Self, Error> {
        let mut lead_buffer = [0; LEAD_SIZE as usize];
        input.read_exact(&mut lead_buffer)?;
        let lead = Lead::parse(&lead_buffer)?;
        let signature_header = Header::parse_signature(input)?;
        let header = Header::parse(input)?;

        Ok(PackageMetadata {
            lead,
            signature: signature_header,
            header,
        })
    }

    /// Write the RPM header to a buffer
    pub fn write(&self, out: &mut impl io::Write) -> Result<(), Error> {
        self.lead.write(out)?;
        self.signature.write_signature(out)?;
        self.header.write(out)?;
        Ok(())
    }

    /// Whether this package is a source package, or not
    #[inline]
    pub fn is_source_package(&self) -> bool {
        self.header.entry_is_present(IndexTag::RPMTAG_SOURCEPACKAGE)
    }

    /// Get the package name
    #[inline]
    pub fn get_name(&self) -> Result<&str, Error> {
        self.header.get_entry_data_as_string(IndexTag::RPMTAG_NAME)
    }

    /// Get the package epoch
    #[inline]
    pub fn get_epoch(&self) -> Result<u32, Error> {
        self.header.get_entry_data_as_u32(IndexTag::RPMTAG_EPOCH)
    }

    /// Get the package version (the upstream version string)
    #[inline]
    pub fn get_version(&self) -> Result<&str, Error> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_VERSION)
    }

    /// Get the package release
    #[inline]
    pub fn get_release(&self) -> Result<&str, Error> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_RELEASE)
    }

    /// Get the package architecture
    #[inline]
    pub fn get_arch(&self) -> Result<&str, Error> {
        self.header.get_entry_data_as_string(IndexTag::RPMTAG_ARCH)
    }

    /// Get the package Nevra
    ///
    /// See: [crate::Nevra]
    #[inline]
    pub fn get_nevra(&'_ self) -> Result<Nevra<'_>, Error> {
        // Epoch defaults to 0 if not present
        let epoch = self.get_epoch().unwrap_or(0);
        Ok(Nevra::new(
            Cow::Borrowed(self.get_name()?),
            Cow::Owned(epoch.to_string()),
            Cow::Borrowed(self.get_version()?),
            Cow::Borrowed(self.get_release()?),
            Cow::Borrowed(self.get_arch()?),
        ))
    }

    /// Get the package vendor - the organization that produced the package
    #[inline]
    pub fn get_vendor(&self) -> Result<&str, Error> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_VENDOR)
    }

    /// Get the package URL. Most often this is the upstream project website for the software
    /// being packaged.
    #[inline]
    pub fn get_url(&self) -> Result<&str, Error> {
        self.header.get_entry_data_as_string(IndexTag::RPMTAG_URL)
    }

    /// Get the package version control URL (of the upstream project)
    #[inline]
    pub fn get_vcs(&self) -> Result<&str, Error> {
        self.header.get_entry_data_as_string(IndexTag::RPMTAG_VCS)
    }

    /// Get the package license
    #[inline]
    pub fn get_license(&self) -> Result<&str, Error> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_LICENSE)
    }

    /// Get the package summary (very brief description of the packaged software)
    #[inline]
    pub fn get_summary(&self) -> Result<&str, Error> {
        self.header
            .get_entry_data_as_i18n_string(IndexTag::RPMTAG_SUMMARY)
    }

    /// Get the package description (a full description of the packaged software)
    #[inline]
    pub fn get_description(&self) -> Result<&str, Error> {
        self.header
            .get_entry_data_as_i18n_string(IndexTag::RPMTAG_DESCRIPTION)
    }

    /// Get the package group (this is deprecated in most packaging guidelines)
    #[inline]
    pub fn get_group(&self) -> Result<&str, Error> {
        self.header
            .get_entry_data_as_i18n_string(IndexTag::RPMTAG_GROUP)
    }

    /// Get the packager, the name of the person that produced this package
    #[inline]
    pub fn get_packager(&self) -> Result<&str, Error> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_PACKAGER)
    }

    /// Get the timestamp when this package was built. This is commonly not present.
    #[inline]
    pub fn get_build_time(&self) -> Result<u64, Error> {
        self.header
            .get_entry_data_as_u32(IndexTag::RPMTAG_BUILDTIME)
            .map(|x| x as u64)
    }

    /// Get the build host on which this package was built. This is commonly not present.
    #[inline]
    pub fn get_build_host(&self) -> Result<&str, Error> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_BUILDHOST)
    }

    /// The cookie is a value that can be used for tracking packages built together, e.g.
    /// packages built in one build operation (from a single source RPM, for example).
    #[inline]
    pub fn get_cookie(&self) -> Result<&str, Error> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_COOKIE)
    }

    /// Get the filename of the source RPM package used to build this package
    #[inline]
    pub fn get_source_rpm(&self) -> Result<&str, Error> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_SOURCERPM)
    }

    /// Get the %pre scriptlet for this package
    #[inline]
    pub fn get_pre_install_script(&self) -> Result<Scriptlet, Error> {
        self.get_scriptlet(PREIN_TAGS)
    }

    /// Get the %post scriptlet for this package
    #[inline]
    pub fn get_post_install_script(&self) -> Result<Scriptlet, Error> {
        self.get_scriptlet(POSTIN_TAGS)
    }

    /// Get the %preun scriptlet for this package
    #[inline]
    pub fn get_pre_uninstall_script(&self) -> Result<Scriptlet, Error> {
        self.get_scriptlet(PREUN_TAGS)
    }

    /// Get the %postun scriptlet for this package
    #[inline]
    pub fn get_post_uninstall_script(&self) -> Result<Scriptlet, Error> {
        self.get_scriptlet(POSTUN_TAGS)
    }

    /// Get the %pretrans scriptlet for this package
    #[inline]
    pub fn get_pre_trans_script(&self) -> Result<Scriptlet, Error> {
        self.get_scriptlet(PRETRANS_TAGS)
    }

    /// Get the %posttrans scriptlet for this package
    #[inline]
    pub fn get_post_trans_script(&self) -> Result<Scriptlet, Error> {
        self.get_scriptlet(POSTTRANS_TAGS)
    }

    /// Get the %preuntrans scriptlet for this package
    #[inline]
    pub fn get_pre_untrans_script(&self) -> Result<Scriptlet, Error> {
        self.get_scriptlet(PREUNTRANS_TAGS)
    }

    /// Get the %postuntrans scriptlet for this package
    #[inline]
    pub fn get_post_untrans_script(&self) -> Result<Scriptlet, Error> {
        self.get_scriptlet(POSTUNTRANS_TAGS)
    }

    /// Get the %verifyscript scriptlet for this package
    #[inline]
    pub fn get_verify_script(&self) -> Result<Scriptlet, Error> {
        self.get_scriptlet(VERIFYSCRIPT_TAGS)
    }

    fn get_dependencies(
        &self,
        names_tag: IndexTag,
        flags_tag: IndexTag,
        versions_tag: IndexTag,
    ) -> Result<Vec<Dependency>, Error> {
        let names = self.header.get_entry_data_as_string_array(names_tag);
        let flags = self.header.get_entry_data_as_u32_array(flags_tag);
        let versions = self.header.get_entry_data_as_string_array(versions_tag);

        match (names, flags, versions) {
            // Return an empty list if the tags are not present
            (
                Err(Error::TagNotFound(_)),
                Err(Error::TagNotFound(_)),
                Err(Error::TagNotFound(_)),
            ) => Ok(vec![]),
            (Ok(names), Ok(flags), Ok(versions)) => {
                let v = Vec::from_iter(itertools::multizip((names, flags, versions)).map(
                    |(name, flags, version)| Dependency {
                        name: name.to_owned(),
                        flags: DependencyFlags::from_bits_retain(flags),
                        version: version.to_owned(),
                    },
                ));
                Ok(v)
            }
            (names, flags, versions) => {
                names?;
                flags?;
                versions?;
                unreachable!()
            }
        }
    }

    fn get_scriptlet(&self, tags: ScriptletIndexTags) -> Result<Scriptlet, Error> {
        let (scriptlet_tag, flags_tag, program_tag) = tags;

        let script = self
            .header
            .get_entry_data_as_string(scriptlet_tag)?
            .to_owned();
        let flags = self
            .header
            .get_entry_data_as_u32(flags_tag)
            .ok()
            .map(ScriptletFlags::from_bits_retain);
        let program = self
            .header
            .get_entry_data_as_string_array(program_tag)
            .ok()
            .map(|v| v.into_iter().map(|s| s.to_owned()).collect());

        Ok(Scriptlet {
            script,
            flags,
            program,
        })
    }

    /// Get package triggers (%triggerin, %triggerun, %triggerpostun, %triggerprein).
    ///
    /// Returns an empty list if no package triggers are defined.
    pub fn get_triggers(&self) -> Result<Vec<Trigger>, Error> {
        self.get_trigger_entries(TRIGGER_TAGS)
    }

    /// Get file triggers (%filetriggerin, %filetriggerun, %filetriggerpostun).
    ///
    /// Returns an empty list if no file triggers are defined.
    pub fn get_file_triggers(&self) -> Result<Vec<Trigger>, Error> {
        self.get_trigger_entries(FILETRIGGER_TAGS)
    }

    /// Get transaction file triggers (%transfiletriggerin, etc.).
    ///
    /// Returns an empty list if no transaction file triggers are defined.
    pub fn get_trans_file_triggers(&self) -> Result<Vec<Trigger>, Error> {
        self.get_trigger_entries(TRANSFILETRIGGER_TAGS)
    }

    fn get_trigger_entries(&self, tags: TriggerIndexTags) -> Result<Vec<Trigger>, Error> {
        let (
            scripts_tag,
            progs_tag,
            _flags_tag,
            names_tag,
            versions_tag,
            cond_flags_tag,
            index_tag,
        ) = tags;

        let scripts = match self.header.get_entry_data_as_string_array(scripts_tag) {
            Ok(v) => v,
            Err(Error::TagNotFound(_)) => return Ok(vec![]),
            Err(e) => return Err(e),
        };

        let progs = self.header.get_entry_data_as_string_array(progs_tag)?;
        let names = self.header.get_entry_data_as_string_array(names_tag)?;
        let versions = self.header.get_entry_data_as_string_array(versions_tag)?;
        let cond_flags = self.header.get_entry_data_as_u32_array(cond_flags_tag)?;
        let indices = self.header.get_entry_data_as_u32_array(index_tag)?;

        // Build triggers: group conditions by their script index
        let num_scripts = scripts.len();
        let mut triggers: Vec<Trigger> = scripts
            .into_iter()
            .zip(progs)
            .map(|(script, prog)| Trigger {
                script: script.to_owned(),
                program: vec![prog.to_owned()],
                conditions: Vec::new(),
            })
            .collect();

        for (name, (version, (flags, idx))) in names.into_iter().zip(
            versions
                .into_iter()
                .zip(cond_flags.into_iter().zip(indices)),
        ) {
            let script_idx = idx as usize;
            if script_idx < num_scripts {
                triggers[script_idx].conditions.push(TriggerCondition {
                    name: name.to_owned(),
                    flags: DependencyFlags::from_bits_retain(flags),
                    version: version.to_owned(),
                });
            }
        }

        Ok(triggers)
    }

    /// Get a list of dependencies which this package "provides"
    ///
    /// These are aliases or capabilities provided by this package which other packages can reference.
    pub fn get_provides(&self) -> Result<Vec<Dependency>, Error> {
        self.get_dependencies(
            IndexTag::RPMTAG_PROVIDENAME,
            IndexTag::RPMTAG_PROVIDEFLAGS,
            IndexTag::RPMTAG_PROVIDEVERSION,
        )
    }

    /// Get a list of dependencies which this package "requires"
    ///
    /// These are packages or capabilities which must be present in order for the package to be
    /// installed.
    pub fn get_requires(&self) -> Result<Vec<Dependency>, Error> {
        self.get_dependencies(
            IndexTag::RPMTAG_REQUIRENAME,
            IndexTag::RPMTAG_REQUIREFLAGS,
            IndexTag::RPMTAG_REQUIREVERSION,
        )
    }

    /// Get a list of dependencies which this package "conflicts" with
    ///
    /// These are packages which must not be present in order for the package to be installed.
    pub fn get_conflicts(&self) -> Result<Vec<Dependency>, Error> {
        self.get_dependencies(
            IndexTag::RPMTAG_CONFLICTNAME,
            IndexTag::RPMTAG_CONFLICTFLAGS,
            IndexTag::RPMTAG_CONFLICTVERSION,
        )
    }

    /// Get a list of dependencies which this package "obsoletes"
    ///
    /// These are packages which are superceded by this package - if this package is installed,
    /// they will be automatically removed if they are present.
    pub fn get_obsoletes(&self) -> Result<Vec<Dependency>, Error> {
        self.get_dependencies(
            IndexTag::RPMTAG_OBSOLETENAME,
            IndexTag::RPMTAG_OBSOLETEFLAGS,
            IndexTag::RPMTAG_OBSOLETEVERSION,
        )
    }

    /// Get a list of dependencies which this package "recommends"
    ///
    /// "rpm" itself will ignore such dependencies, but a dependency solver may elect to treat them
    /// as though they were "requires".  Unlike "requires" however, if installing a package listed
    /// as a "recommends" would cause errors, it may be ignored without error.
    pub fn get_recommends(&self) -> Result<Vec<Dependency>, Error> {
        self.get_dependencies(
            IndexTag::RPMTAG_RECOMMENDNAME,
            IndexTag::RPMTAG_RECOMMENDFLAGS,
            IndexTag::RPMTAG_RECOMMENDVERSION,
        )
    }

    /// Get a list of dependencies which this package "suggests"
    ///
    /// "rpm" itself will ignore such dependencies, but a dependency solver may elect to display
    /// them to the user to be optionally installed.
    pub fn get_suggests(&self) -> Result<Vec<Dependency>, Error> {
        self.get_dependencies(
            IndexTag::RPMTAG_SUGGESTNAME,
            IndexTag::RPMTAG_SUGGESTFLAGS,
            IndexTag::RPMTAG_SUGGESTVERSION,
        )
    }

    /// Get a list of reverse-dependencies which this package "enhances"
    ///
    /// "rpm" itself will ignore such dependencies, but a dependency solver may elect to display
    /// this package to the user to be optionally installed when a package matching the "enhances"
    /// dependency is installed.
    pub fn get_enhances(&self) -> Result<Vec<Dependency>, Error> {
        self.get_dependencies(
            IndexTag::RPMTAG_ENHANCENAME,
            IndexTag::RPMTAG_ENHANCEFLAGS,
            IndexTag::RPMTAG_ENHANCEVERSION,
        )
    }

    /// Get a list of reverse-dependencies which this package "supplements"
    ///
    /// "rpm" itself will ignore such dependencies, but a dependency solver may elect to treat this
    /// package as a "requires" when the matching package is installed. Unlike a "requires" however,
    /// if installing it would cause errors, it can be ignored without error.
    pub fn get_supplements(&self) -> Result<Vec<Dependency>, Error> {
        self.get_dependencies(
            IndexTag::RPMTAG_SUPPLEMENTNAME,
            IndexTag::RPMTAG_SUPPLEMENTFLAGS,
            IndexTag::RPMTAG_SUPPLEMENTVERSION,
        )
    }

    /// An RPM package is comprised of several segments - the Lead, Signature Header, Header, and Payload.
    /// This function returns the computed (byte) boundaries between those segments in the package file
    /// as if it were written out on-disk.
    ///
    /// ```
    /// # use rpm::Package;
    /// # let package = Package::open("tests/assets/RPMS/v4/rpm-basic-2.3.4-5.el9.noarch.rpm").unwrap();
    /// let offsets = package.metadata.get_package_segment_offsets();
    /// let lead = offsets.lead..offsets.signature_header;
    /// let sig_header = offsets.signature_header..offsets.header;
    /// let header = offsets.header..offsets.payload;
    /// let payload = offsets.payload..;
    /// ```
    pub fn get_package_segment_offsets(&self) -> PackageSegmentOffsets {
        // Lead is 96 bytes.

        // Each Header starts like this (16 bytes)
        // 3 bytes for the magic
        // 1 byte RPM version number - always 1
        // 4 reserved bytes (no meaning, just padding)
        // 4 bytes for the number of entries in the index (u32)
        // 4 bytes for the length of the data section (u32)

        // Next comes a series of index entries
        // Each index entry is 16 bytes
        // 4 bytes for the tag (u32)
        // 4 bytes for the tag data type (u32)
        // 4 bytes for the offset relative to the beginning of the data store
        // 4 bytes for the count that contains the number of data items pointed to by the index entry

        // After the header entries comes the data section. This stores the data pointed to by
        // the offsets within each index entry.

        let sig_header_start = LEAD_SIZE;
        let sig_header_size = self.signature.size();
        let padding = self.signature.padding_required();

        let header_start = sig_header_start + sig_header_size + padding;
        let header_size = self.header.size();

        let payload_start = header_start + header_size;

        PackageSegmentOffsets {
            lead: 0,
            signature_header: sig_header_start as u64,
            header: header_start as u64,
            payload: payload_start as u64,
        }
    }

    /// Get the sum of the sizes of all files present in the package payload
    pub fn get_installed_size(&self) -> Result<u64, Error> {
        self.header
            .get_entry_data_as_u64(IndexTag::RPMTAG_LONGSIZE)
            .or_else(|_e| {
                self.header
                    .get_entry_data_as_u32(IndexTag::RPMTAG_SIZE)
                    .map(|v| v as u64)
            })
    }

    #[inline]
    pub fn get_payload_compressor(&self) -> Result<CompressionType, Error> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_PAYLOADCOMPRESSOR)
            .map_or_else(
                |e| {
                    if matches!(e, Error::TagNotFound(_)) {
                        Ok(CompressionType::None)
                    } else {
                        Err(e)
                    }
                },
                CompressionType::from_str,
            )
    }

    /// Extract a the set of contained file names.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let package = rpm::Package::open("tests/assets/RPMS/v4/rpm-basic-2.3.4-5.el9.noarch.rpm")?;
    /// for path in package.metadata.get_file_paths()? {
    ///     println!("{}", path.display());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn get_file_paths(&self) -> Result<Vec<PathBuf>, Error> {
        // reconstruct the messy de-constructed paths
        let basenames = self
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_BASENAMES);
        let biject = self
            .header
            .get_entry_data_as_u32_array(IndexTag::RPMTAG_DIRINDEXES);
        let dirs = self
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_DIRNAMES);

        // Return an empty list if the tags are not present
        match (basenames, biject, dirs) {
            (
                Err(Error::TagNotFound(_)),
                Err(Error::TagNotFound(_)),
                Err(Error::TagNotFound(_)),
            ) => Ok(vec![]),
            (Ok(basenames), Ok(biject), Ok(dirs)) => {
                let n = dirs.len();

                let v = basenames
                    .iter()
                    .zip(biject.into_iter())
                    .try_fold::<Vec<PathBuf>, _, _>(
                        Vec::<PathBuf>::with_capacity(basenames.len()),
                        |mut acc, item| {
                            let (basename, dir_index) = item;
                            if let Some(dir) = dirs.get(dir_index as usize) {
                                acc.push(Path::new(dir).join(basename));
                                Ok(acc)
                            } else {
                                Err(Error::InvalidTagIndex {
                                    tag: IndexTag::RPMTAG_DIRINDEXES.to_string(),
                                    index: dir_index,
                                    bound: n as u32,
                                })
                            }
                        },
                    )?;
                Ok(v)
            }
            (basenames, biject, dirs) => {
                basenames?;
                biject?;
                dirs?;
                unreachable!()
            }
        }
    }

    /// The digest algorithm used per file.
    ///
    /// Note that this is not necessarily the same as the digest used for headers.
    pub fn get_file_digest_algorithm(&self) -> Result<DigestAlgorithm, Error> {
        self.header
            .get_entry_data_as_u32(IndexTag::RPMTAG_FILEDIGESTALGO)
            .and_then(|x| {
                DigestAlgorithm::from_u32(x).ok_or_else(|| Error::InvalidTagValueEnumVariant {
                    tag: IndexTag::RPMTAG_FILEDIGESTALGO.to_string(),
                    variant: x,
                })
            })
    }

    /// Get a list of metadata about the files in the RPM, without the file contents.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let package = rpm::Package::open("tests/assets/RPMS/v4/rpm-basic-2.3.4-5.el9.noarch.rpm")?;
    /// for entry in package.metadata.get_file_entries()? {
    ///     println!("{} is {} bytes", entry.path.display(), entry.size);
    /// }
    /// # Ok(()) }
    /// ```
    pub fn get_file_entries(&self) -> Result<Vec<FileEntry>, Error> {
        // rpm does not encode it, if it is the default md5
        let algorithm = self
            .get_file_digest_algorithm()
            .unwrap_or(DigestAlgorithm::Md5);
        //
        let modes = self
            .header
            .get_entry_data_as_u16_array(IndexTag::RPMTAG_FILEMODES);
        if let Err(Error::TagNotFound(_)) = modes {
            return Ok(Vec::new());
        }

        let users = self
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_FILEUSERNAME);
        let groups = self
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_FILEGROUPNAME);
        let digests = self
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_FILEDIGESTS);
        let mtimes = self
            .header
            .get_entry_data_as_u32_array(IndexTag::RPMTAG_FILEMTIMES);
        let sizes = self
            .header
            .get_entry_data_as_u64_array(IndexTag::RPMTAG_LONGFILESIZES)
            .or_else(|_e| {
                self.header
                    .get_entry_data_as_u32_array(IndexTag::RPMTAG_FILESIZES)
                    .map(|file_sizes| {
                        file_sizes
                            .into_iter()
                            .map(|file_size| file_size as _)
                            .collect::<Vec<u64>>()
                    })
            });
        let flags = self
            .header
            .get_entry_data_as_u32_array(IndexTag::RPMTAG_FILEFLAGS);

        // Look for the file capabilities tag, but it's not required so don't error out if it's not
        // present
        let caps = match self
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_FILECAPS)
        {
            Ok(caps) => Ok(Some(caps)),
            Err(Error::TagNotFound(_)) => Ok(None),
            Err(e) => return Err(e),
        };
        // TODO: verify this is correct behavior for links?
        let links = self
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_FILELINKTOS);
        let ima_signatures = match self
            .signature
            .get_entry_data_as_string_array(IndexSignatureTag::RPMSIGTAG_FILESIGNATURES)
        {
            Ok(ima_signatures) => Ok(Some(ima_signatures)),
            Err(Error::TagNotFound(_)) => Ok(None),
            Err(e) => return Err(e),
        };

        match (
            modes,
            users,
            groups,
            digests,
            mtimes,
            sizes,
            flags,
            caps,
            links,
            ima_signatures,
        ) {
            (
                Ok(modes),
                Ok(users),
                Ok(groups),
                Ok(digests),
                Ok(mtimes),
                Ok(sizes),
                Ok(flags),
                Ok(caps),
                Ok(links),
                Ok(ima_signatures),
            ) => {
                let paths = self.get_file_paths()?;
                let n = paths.len();

                let v = itertools::multizip((
                    paths.into_iter(),
                    users,
                    groups,
                    modes,
                    digests,
                    mtimes,
                    sizes,
                    flags,
                    links,
                ))
                .enumerate()
                .try_fold::<Vec<FileEntry>, _, Result<_, Error>>(
                    Vec::with_capacity(n),
                    |mut acc, (idx, (path, user, group, mode, digest, mtime, size, flags, linkto))| {
                        let digest = if digest.is_empty() {
                            None
                        } else {
                            Some(FileDigest::new(algorithm, digest)?)
                        };
                        let cap = match &caps {
                            Some(caps) => caps.get(idx).map(|s| (*s).to_owned()),
                            None => None,
                        };
                        let ima_signature: Option<String> = match &ima_signatures {
                            Some(ima_signatures) => ima_signatures.get(idx).map(|s| (*s).to_owned()),
                            None => None,
                        };
                        acc.push(FileEntry {
                            path,
                            ownership: FileOwnership {
                                user: user.to_owned(),
                                group: group.to_owned(),
                            },
                            mode: mode.into(),
                            modified_at: crate::Timestamp(mtime),
                            digest,
                            flags: FileFlags::from_bits_retain(flags),
                            size: size as usize,
                            caps: cap,
                            linkto: linkto.to_owned(),
                            ima_signature,
                        });
                        Ok(acc)
                    },
                )?;
                Ok(v)
            }
            (
                Err(Error::TagNotFound(_)),
                Err(Error::TagNotFound(_)),
                Err(Error::TagNotFound(_)),
                Err(Error::TagNotFound(_)),
                Err(Error::TagNotFound(_)),
                Err(Error::TagNotFound(_)),
                Err(Error::TagNotFound(_)),
                Err(Error::TagNotFound(_)),
                Err(Error::TagNotFound(_)),
                Err(Error::TagNotFound(_)),
            ) => Ok(vec![]),
            (modes, users, groups, digests, mtimes, sizes, flags, caps, links, ima_signatures) => {
                modes?;
                users?;
                groups?;
                digests?;
                mtimes?;
                sizes?;
                flags?;
                caps?;
                links?;
                ima_signatures?;
                unreachable!()
            }
        }
    }

    /// Return a list of changelog entries
    pub fn get_changelog_entries(&self) -> Result<Vec<ChangelogEntry>, Error> {
        let names = self
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_CHANGELOGNAME);
        let timestamps = self
            .header
            .get_entry_data_as_u32_array(IndexTag::RPMTAG_CHANGELOGTIME);
        let descriptions = self
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_CHANGELOGTEXT);

        // Return an empty list if the tags are not present
        match (names, timestamps, descriptions) {
            (
                Err(Error::TagNotFound(_)),
                Err(Error::TagNotFound(_)),
                Err(Error::TagNotFound(_)),
            ) => Ok(vec![]),
            (Ok(names), Ok(timestamps), Ok(descriptions)) => {
                let v = Vec::from_iter(itertools::multizip((names, timestamps, descriptions)).map(
                    |(name, timestamp, description)| ChangelogEntry {
                        name: name.to_owned(),
                        timestamp: timestamp as u64,
                        description: description.to_owned(),
                    },
                ));
                Ok(v)
            }
            (name, timestamp, description) => {
                name?;
                timestamp?;
                description?;
                unreachable!()
            }
        }
    }

    /// Return the raw bytes of each signature in the package's signature header.
    ///
    /// OpenPGP signatures are base64-decoded; legacy RSA/DSA signatures are
    /// returned as borrowed slices from the header store.
    pub fn raw_signatures(&self) -> Result<Vec<Cow<'_, [u8]>>, Error> {
        let openpgp_sigs = self
            .signature
            .get_entry_data_as_string_array(IndexSignatureTag::RPMSIGTAG_OPENPGP);

        // If RPMSIGTAG_OPENPGP exists, then the other tags (which should contain the same info) are not checked
        if let Ok(openpgp_sigs) = openpgp_sigs {
            openpgp_sigs
                .iter()
                .map(|s| decode_sig(s).map(Cow::Owned))
                .collect()
        } else {
            // Legacy signature tags
            for sig_result in [
                self.signature
                    .get_entry_data_as_binary(IndexSignatureTag::RPMSIGTAG_RSA),
                self.signature
                    .get_entry_data_as_binary(IndexSignatureTag::RPMSIGTAG_DSA),
            ] {
                match sig_result {
                    Ok(sig_bytes) => return Ok(vec![Cow::Borrowed(sig_bytes)]),
                    Err(Error::TagNotFound(_)) => continue,
                    Err(e) => return Err(e),
                }
            }

            Ok(Vec::new())
        }
    }

    #[cfg(feature = "signature-pgp")]
    fn parse_signature_packets(&self) -> Result<Vec<pgp::packet::Signature>, Error> {
        self.raw_signatures()?
            .iter()
            .map(|bytes| Verifier::parse_signature(bytes))
            .collect()
    }

    /// Return parsed information about each OpenPGP header signature in the package.
    ///
    /// Does not return legacy header + payload signatures (v3 signatures).
    ///
    /// Returns an empty `Vec` if the package is unsigned.
    #[cfg(feature = "signature-pgp")]
    pub fn signatures(&self) -> Result<Vec<signature::pgp::SignatureInfo>, Error> {
        Ok(self
            .parse_signature_packets()?
            .iter()
            .map(signature::pgp::SignatureInfo::from_pgp_signature)
            .collect())
    }

    /// Check header digests and return a detailed report.
    ///
    /// Only header digests are checked; payload digest fields are set to
    /// [`DigestStatus::NotChecked`]. To check all digests including payload,
    /// use [`Package::check_digests`].
    pub fn check_digests(&self) -> Result<DigestReport, Error> {
        let mut header = Vec::<u8>::with_capacity(1024);
        self.header.write(&mut header)?;

        // --- Header digests (from sig header) ---

        let sha1_header = DigestStatus::check_digest_against_tag::<sha1::Sha1>(
            self.signature
                .get_entry_data_as_string(IndexSignatureTag::RPMSIGTAG_SHA1),
            header.as_slice(),
        );

        let sha256_header = DigestStatus::check_digest_against_tag::<sha2::Sha256>(
            self.signature
                .get_entry_data_as_string(IndexSignatureTag::RPMSIGTAG_SHA256),
            header.as_slice(),
        );

        let sha3_256_header = DigestStatus::check_digest_against_tag::<sha3::Sha3_256>(
            self.signature
                .get_entry_data_as_string(IndexSignatureTag::RPMSIGTAG_SHA3_256),
            header.as_slice(),
        );

        Ok(DigestReport {
            sha1_header,
            sha256_header,
            sha3_256_header,
            payload_sha256: DigestStatus::NotChecked,
            payload_sha512: DigestStatus::NotChecked,
            payload_sha3_256: DigestStatus::NotChecked,
        })
    }

    /// Verify header digests.
    ///
    /// This is a convenience wrapper around [`check_digests`](Self::check_digests)
    /// that collapses the detailed report into a pass/fail `Result`.
    ///
    /// Only header digests are verified. To verify all digests including payload,
    /// use [`Package::verify_digests`].
    pub fn verify_digests(&self) -> Result<(), Error> {
        let digests = self.check_digests()?;

        if !digests.has_header_digest() {
            return Err(Error::NoHeaderDigestError);
        }

        digests.result()
    }

    /// Verify header-only signatures.
    ///
    /// This is a convenience wrapper around [`check_signatures`](Self::check_signatures)
    /// that collapses the detailed report into a pass/fail `Result`.
    ///
    /// Legacy v3 signatures that cover the payload are not checked.
    /// To verify all signatures, use [`Package::verify_signature`].
    #[cfg(feature = "signature-meta")]
    pub fn verify_signature<V>(&self, verifier: V) -> Result<(), Error>
    where
        V: signature::Verifying<Signature = Vec<u8>>,
    {
        self.check_signatures(verifier)?.into_result()
    }

    /// Check header digests and verify header-only signatures, returning a detailed report.
    ///
    /// Payload digest fields are set to [`DigestStatus::NotChecked`].
    /// To check everything, use [`Package::check_signatures`].
    #[cfg(feature = "signature-pgp")]
    pub fn check_signatures<V>(&self, verifier: V) -> Result<SignatureReport, Error>
    where
        V: signature::Verifying<Signature = Vec<u8>>,
    {
        let digests = self.check_digests()?;

        let mut header_bytes = Vec::<u8>::with_capacity(1024);
        self.header.write(&mut header_bytes)?;

        let mut signatures = Vec::new();
        for sig_bytes in &self.raw_signatures()? {
            let parsed = Verifier::parse_signature(sig_bytes)?;
            let info = signature::pgp::SignatureInfo::from_pgp_signature(&parsed);
            let error = verifier.verify(header_bytes.as_slice(), sig_bytes).err();
            signatures.push(SignatureCheckResult { info, error });
        }

        Ok(SignatureReport {
            digests,
            signatures,
        })
    }
}

pub struct FileIterator<'a> {
    file_entries: Vec<FileEntry>,
    archive: Box<dyn io::Read + 'a>,
    count: usize,
}

#[derive(Debug)]
pub struct RpmFile {
    pub metadata: FileEntry,
    pub content: Vec<u8>,
}

impl Iterator for FileIterator<'_> {
    type Item = Result<RpmFile, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count >= self.file_entries.len() {
            return None;
        }

        // @todo: probably safe to hand out a reference instead of cloning, just a bit more painful
        let file_entry = self.file_entries[self.count].clone();
        self.count += 1;

        // Ghost files are not in the payload archive, so return them immediately with empty content
        if file_entry.flags.contains(FileFlags::GHOST) {
            return Some(Ok(RpmFile {
                metadata: file_entry,
                content: Vec::new(),
            }));
        }

        let reader = payload::Reader::new(&mut self.archive, &self.file_entries);

        match reader {
            Ok(mut entry_reader) => {
                if entry_reader.is_trailer() {
                    return None;
                }

                let mut content = Vec::new();

                if let Err(e) = entry_reader.read_to_end(&mut content) {
                    return Some(Err(Error::Io(e)));
                }
                if let Err(e) = entry_reader.finish() {
                    return Some(Err(Error::Io(e)));
                }

                Some(Ok(RpmFile {
                    metadata: file_entry,
                    content,
                }))
            }
            Err(e) => Some(Err(Error::Io(e))),
        }
    }
}

impl ExactSizeIterator for FileIterator<'_> {
    fn len(&self) -> usize {
        self.file_entries.len() - self.count
    }
}
