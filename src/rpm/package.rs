use std::path::PathBuf;

use chrono::offset::TimeZone;
#[cfg(feature = "async-futures")]
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use num_traits::FromPrimitive;

use super::headers::*;
use super::Lead;

use crate::constants::*;
use crate::errors::*;

#[cfg(feature = "signature-meta")]
use crate::sequential_cursor::SeqCursor;
#[cfg(feature = "signature-meta")]
use crate::signature;

#[cfg(feature = "signature-meta")]
use std::io::{Seek, SeekFrom};

/// A complete rpm file.
///
/// Can either be created using the [`RPMPackageBuilder`](super::builder::RPMPackageBuilder)
/// or used with [`parse`](`self::RPMPackage::parse`) to obtain from a file.
#[derive(Debug)]
pub struct RPMPackage {
    /// Header and metadata structures.
    ///
    /// Contains the constant lead as well as the metadata store.
    pub metadata: RPMPackageMetadata,
    /// The compressed or uncompressed files.
    pub content: Vec<u8>,
}

impl RPMPackage {
    #[cfg(feature = "async-futures")]
    pub async fn parse_async<I: AsyncRead + Unpin>(input: &mut I) -> Result<Self, RPMError> {
        let metadata = RPMPackageMetadata::parse_async(input).await?;
        let mut content = Vec::new();
        input.read_to_end(&mut content).await?;
        Ok(RPMPackage { metadata, content })
    }

    pub fn parse<T: std::io::BufRead>(input: &mut T) -> Result<Self, RPMError> {
        let metadata = RPMPackageMetadata::parse(input)?;
        let mut content = Vec::new();
        input.read_to_end(&mut content)?;
        Ok(RPMPackage { metadata, content })
    }

    pub fn write<W: std::io::Write>(&self, out: &mut W) -> Result<(), RPMError> {
        self.metadata.write(out)?;
        out.write_all(&self.content)?;
        Ok(())
    }

    #[cfg(feature = "async-futures")]
    pub async fn write_async<W: AsyncWrite + Unpin>(&self, out: &mut W) -> Result<(), RPMError> {
        self.metadata.write_async(out).await?;
        out.write_all(&self.content).await?;
        Ok(())
    }

    // TODO allow passing an external signer/verifier

    /// sign all headers (except for the lead) using an external key and store it as the initial header
    #[cfg(feature = "signature-meta")]
    pub fn sign<S>(&mut self, signer: S) -> Result<(), RPMError>
    where
        S: signature::Signing<signature::algorithm::RSA, Signature = Vec<u8>>,
    {
        use std::convert::TryInto;
        use std::io::Read;

        // create a temporary byte repr of the header
        // and re-create all hashes

        let mut header_bytes = Vec::<u8>::with_capacity(1024);
        // make sure to not hash any previous signatures in the header
        self.metadata.header.write(&mut header_bytes)?;

        let mut header_and_content_cursor =
            SeqCursor::new(&[header_bytes.as_slice(), self.content.as_slice()]);

        let digest_md5 = {
            use md5::Digest;
            let mut hasher = md5::Md5::default();
            {
                // avoid loading it into memory all at once
                // since the content could be multiple 100s of MBs
                let mut buf = [0u8; 256];
                while let Ok(n) = header_and_content_cursor.read(&mut buf[..]) {
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buf[0..n]);
                }
            }
            let hash_result = hasher.finalize();
            hash_result.to_vec()
        };

        header_and_content_cursor.seek(SeekFrom::Start(0))?;

        let digest_sha1 = {
            use sha1::Digest;
            let mut hasher = sha1::Sha1::default();
            hasher.update(&header_bytes);
            let digest = hasher.finalize();
            hex::encode(digest)
        };

        let rsa_signature_spanning_header_only = signer.sign(header_bytes.as_slice())?;

        let rsa_signature_spanning_header_and_archive =
            signer.sign(&mut header_and_content_cursor)?;

        // NOTE: size stands for the combined size of header and payload.
        self.metadata.signature = Header::<IndexSignatureTag>::new_signature_header(
            header_and_content_cursor
                .len()
                .try_into()
                .expect("headers + payload can't be larger than 4gb"),
            &digest_md5,
            digest_sha1,
            rsa_signature_spanning_header_only.as_slice(),
            rsa_signature_spanning_header_and_archive.as_slice(),
        );

        Ok(())
    }

    /// Verify the signature as present within the RPM package.
    ///
    ///
    #[cfg(feature = "signature-meta")]
    pub fn verify_signature<V>(&self, verifier: V) -> Result<(), RPMError>
    where
        V: signature::Verifying<signature::algorithm::RSA, Signature = Vec<u8>>,
    {
        // TODO retval should be SIGNATURE_VERIFIED or MISMATCH, not just an error

        let mut header_bytes = Vec::<u8>::with_capacity(1024);
        self.metadata.header.write(&mut header_bytes)?;

        let signature_header_only = self
            .metadata
            .signature
            .get_entry_data_as_binary(IndexSignatureTag::RPMSIGTAG_RSA)?;

        crate::signature::echo_signature("signature_header(header only)", signature_header_only);

        let signature_header_and_content = self
            .metadata
            .signature
            .get_entry_data_as_binary(IndexSignatureTag::RPMSIGTAG_PGP)?;

        crate::signature::echo_signature(
            "signature_header(header and content)",
            signature_header_and_content,
        );

        verifier.verify(header_bytes.as_slice(), signature_header_only)?;

        let header_and_content_cursor =
            SeqCursor::new(&[header_bytes.as_slice(), self.content.as_slice()]);

        verifier.verify(header_and_content_cursor, signature_header_and_content)?;

        Ok(())
    }
}

#[derive(PartialEq, Debug)]
pub struct RPMPackageMetadata {
    pub lead: Lead,
    pub signature: Header<IndexSignatureTag>,
    pub header: Header<IndexTag>,
}

impl RPMPackageMetadata {
    #[cfg(feature = "async-futures")]
    pub async fn parse_async<T: AsyncRead + Unpin>(input: &mut T) -> Result<Self, RPMError> {
        let mut lead_buffer = [0; LEAD_SIZE];
        input.read_exact(&mut lead_buffer).await?;
        let lead = Lead::parse(&lead_buffer)?;
        let signature_header = Header::parse_signature_async(input).await?;
        let header = Header::parse_async(input).await?;
        Ok(RPMPackageMetadata {
            lead,
            signature: signature_header,
            header,
        })
    }

    pub(crate) fn parse<T: std::io::BufRead>(input: &mut T) -> Result<Self, RPMError> {
        let mut lead_buffer = [0; LEAD_SIZE];
        input.read_exact(&mut lead_buffer)?;
        let lead = Lead::parse(&lead_buffer)?;
        let signature_header = Header::parse_signature(input)?;
        let header = Header::parse(input)?;
        Ok(RPMPackageMetadata {
            lead,
            signature: signature_header,
            header,
        })
    }

    pub(crate) fn write<W: std::io::Write>(&self, out: &mut W) -> Result<(), RPMError> {
        self.lead.write(out)?;
        self.signature.write_signature(out)?;
        self.header.write(out)?;
        Ok(())
    }

    #[cfg(feature = "async-futures")]
    pub async fn write_async<W: AsyncWrite + Unpin>(&self, out: &mut W) -> Result<(), RPMError> {
        self.lead.write_async(out).await?;
        self.signature.write_signature_async(out).await?;
        self.header.write_async(out).await?;
        Ok(())
    }

    #[inline]
    pub fn is_source_package(&self) -> bool {
        self.header
            .get_entry_data_as_u32(IndexTag::RPMTAG_SOURCEPACKAGE)
            .is_ok()
    }

    #[inline]
    pub fn get_name(&self) -> Result<&str, RPMError> {
        self.header.get_entry_data_as_string(IndexTag::RPMTAG_NAME)
    }

    #[inline]
    pub fn get_epoch(&self) -> Result<u32, RPMError> {
        self.header.get_entry_data_as_u32(IndexTag::RPMTAG_EPOCH)
    }

    #[inline]
    pub fn get_version(&self) -> Result<&str, RPMError> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_VERSION)
    }

    #[inline]
    pub fn get_release(&self) -> Result<&str, RPMError> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_RELEASE)
    }

    #[inline]
    pub fn get_arch(&self) -> Result<&str, RPMError> {
        self.header.get_entry_data_as_string(IndexTag::RPMTAG_ARCH)
    }

    #[inline]
    pub fn get_vendor(&self) -> Result<&str, RPMError> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_VENDOR)
    }

    #[inline]
    pub fn get_url(&self) -> Result<&str, RPMError> {
        self.header.get_entry_data_as_string(IndexTag::RPMTAG_URL)
    }

    #[inline]
    pub fn get_license(&self) -> Result<&str, RPMError> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_LICENSE)
    }

    // TODO: internationalized strings
    // get_summary, get_description, get_group

    #[inline]
    pub fn get_packager(&self) -> Result<&str, RPMError> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_PACKAGER)
    }

    #[inline]
    pub fn get_build_time(&self) -> Result<u64, RPMError> {
        self.header
            .get_entry_data_as_u32(IndexTag::RPMTAG_BUILDTIME)
            .map(|x| x as u64)
    }

    #[inline]
    pub fn get_build_host(&self) -> Result<&str, RPMError> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_BUILDHOST)
    }

    #[inline]
    pub fn get_source_rpm(&self) -> Result<&str, RPMError> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_SOURCERPM)
    }

    // TODO: get_provides, get_requires, etc.
    // TODO: get_header_byte_range
    // TODO: get_archive_size, get_installed_size

    #[inline]
    pub fn get_payload_format(&self) -> Result<&str, RPMError> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_PAYLOADFORMAT)
    }

    #[inline]
    pub fn get_payload_compressor(&self) -> Result<&str, RPMError> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_PAYLOADCOMPRESSOR)
    }

    #[inline]
    pub fn get_file_checksums(&self) -> Result<&[String], RPMError> {
        self.header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_FILEDIGESTS)
    }

    #[inline]
    pub fn get_file_ima_signatures(&self) -> Result<&[String], RPMError> {
        self.signature
            .get_entry_data_as_string_array(IndexSignatureTag::RPMSIGTAG_FILESIGNATURES)
    }

    /// Extract a the set of contained file names.
    pub fn get_file_paths(&self) -> Result<Vec<PathBuf>, RPMError> {
        // reconstruct the messy de-constructed paths
        let base = self
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_BASENAMES)?;
        let biject = self
            .header
            .get_entry_data_as_u32_array(IndexTag::RPMTAG_DIRINDEXES)?;
        let dirs = self
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_DIRNAMES)?;

        let n = dirs.len();
        let v = base
            .iter()
            .zip(biject.into_iter())
            .try_fold::<Vec<PathBuf>, _, _>(
                Vec::<PathBuf>::with_capacity(base.len()),
                |mut acc, item| {
                    let (base, dir_index) = item;
                    if let Some(dir) = dirs.get(dir_index as usize) {
                        acc.push(PathBuf::from(dir).join(base));
                        Ok(acc)
                    } else {
                        Err(RPMError::InvalidTagIndex {
                            tag: IndexTag::RPMTAG_DIRINDEXES.to_string(),
                            index: dir_index,
                            bound: n as u32,
                        })
                    }
                },
            )?;
        Ok(v)
    }

    /// The digest algorithm used per file.
    ///
    /// Note that this is not necessarily the same as the digest
    /// used for headers.
    pub fn get_file_digest_algorithm(&self) -> Result<FileDigestAlgorithm, RPMError> {
        self.header
            .get_entry_data_as_u32(IndexTag::RPMTAG_FILEDIGESTALGO)
            .and_then(|x| {
                FileDigestAlgorithm::from_u32(x).ok_or_else(|| {
                    RPMError::InvalidTagValueEnumVariant {
                        tag: IndexTag::RPMTAG_FILEDIGESTALGO.to_string(),
                        variant: x,
                    }
                })
            })
    }

    /// Extract a the set of contained file names including the additional metadata.
    pub fn get_file_entries(&self) -> Result<Vec<FileEntry>, RPMError> {
        // rpm does not encode it, if it is the default md5
        let algorithm = self.get_file_digest_algorithm().unwrap_or_default();
        //
        let modes = self
            .header
            .get_entry_data_as_u16_array(IndexTag::RPMTAG_FILEMODES)?;
        let users = self
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_FILEUSERNAME)?;
        let groups = self
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_FILEGROUPNAME)?;
        let digests = self
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_FILEDIGESTS)?;
        let mtimes = self
            .header
            .get_entry_data_as_u32_array(IndexTag::RPMTAG_FILEMTIMES)?;
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
            })?;
        let flags = self
            .header
            .get_entry_data_as_u32_array(IndexTag::RPMTAG_FILEFLAGS)?;
        // @todo
        // let caps = self.get_entry_i32_array_data(IndexTag::RPMTAG_FILECAPS)?;

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
        ))
        .try_fold::<Vec<FileEntry>, _, Result<_, RPMError>>(
            Vec::with_capacity(n),
            |mut acc, (path, user, group, mode, digest, mtime, size, flags)| {
                let digest = if digest.is_empty() {
                    None
                } else {
                    Some(FileDigest::load_from_str(algorithm, digest)?)
                };
                let utc = chrono::Utc;
                acc.push(FileEntry {
                    path,
                    ownership: FileOwnership {
                        user: user.to_owned(),
                        group: group.to_owned(),
                    },
                    mode: mode.into(),
                    modified_at: utc.timestamp_opt(mtime as i64, 0u32).unwrap(), // shouldn't fail as we are using 0 nanoseconds
                    digest,
                    category: FileCategory::from_u32(flags).unwrap_or_default(),
                    size: size as usize,
                });
                Ok(acc)
            },
        )?;
        Ok(v)
    }

    // TODO: get_changelog_entries()
}
