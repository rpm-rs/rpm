use std::io::BufReader;
use std::path::{Path, PathBuf};

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
use std::io::Seek;

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
    /// Open and parse a file at the provided path as an RPM package.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, RPMError> {
        let rpm_file = std::fs::File::open(path.as_ref())?;
        let mut buf_reader = BufReader::new(rpm_file);
        Self::parse(&mut buf_reader)
    }

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

        header_and_content_cursor.rewind()?;

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
            .find_entry_or_err(&IndexTag::RPMTAG_SOURCEPACKAGE)
            .is_ok()
    }

    #[inline]
    pub fn get_name(&self) -> Result<&str, RPMError> {
        self.header.get_entry_data_as_string(IndexTag::RPMTAG_NAME)
    }

    // TODO: infalliable?  default to 0
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
    pub fn get_vcs(&self) -> Result<&str, RPMError> {
        self.header.get_entry_data_as_string(IndexTag::RPMTAG_VCS)
    }

    #[inline]
    pub fn get_license(&self) -> Result<&str, RPMError> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_LICENSE)
    }

    #[inline]
    pub fn get_summary(&self) -> Result<&str, RPMError> {
        self.header
            .get_entry_data_as_i18n_string(IndexTag::RPMTAG_SUMMARY)
    }

    #[inline]
    pub fn get_description(&self) -> Result<&str, RPMError> {
        self.header
            .get_entry_data_as_i18n_string(IndexTag::RPMTAG_DESCRIPTION)
    }

    #[inline]
    pub fn get_group(&self) -> Result<&str, RPMError> {
        self.header
            .get_entry_data_as_i18n_string(IndexTag::RPMTAG_GROUP)
    }

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

    fn get_dependencies(
        &self,
        names_tag: IndexTag,
        flags_tag: IndexTag,
        versions_tag: IndexTag,
    ) -> Result<Vec<Dependency>, RPMError> {
        let names = self.header.get_entry_data_as_string_array(names_tag);
        let flags = self.header.get_entry_data_as_u32_array(flags_tag);
        let versions = self.header.get_entry_data_as_string_array(versions_tag);

        match (names, flags, versions) {
            // Return an empty list if the tags are not present
            (
                Err(RPMError::TagNotFound(_)),
                Err(RPMError::TagNotFound(_)),
                Err(RPMError::TagNotFound(_)),
            ) => Ok(vec![]),
            (Ok(names), Ok(flags), Ok(versions)) => {
                let v = Vec::from_iter(itertools::multizip((names, flags, versions)).map(
                    |(name, flags, version)| Dependency {
                        dep_name: name.to_owned(),
                        sense: flags,
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

    /// Get a list of dependencies which this package "provides"
    ///
    /// These are aliases or capabilities provided by this package which other packages can reference.
    pub fn get_provides(&self) -> Result<Vec<Dependency>, RPMError> {
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
    pub fn get_requires(&self) -> Result<Vec<Dependency>, RPMError> {
        self.get_dependencies(
            IndexTag::RPMTAG_REQUIRENAME,
            IndexTag::RPMTAG_REQUIREFLAGS,
            IndexTag::RPMTAG_REQUIREVERSION,
        )
    }

    /// Get a list of dependencies which this package "conflicts" with
    ///
    /// These are packages which must not be present in order for the package to be installed.
    pub fn get_conflicts(&self) -> Result<Vec<Dependency>, RPMError> {
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
    pub fn get_obsoletes(&self) -> Result<Vec<Dependency>, RPMError> {
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
    pub fn get_recommends(&self) -> Result<Vec<Dependency>, RPMError> {
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
    pub fn get_suggests(&self) -> Result<Vec<Dependency>, RPMError> {
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
    pub fn get_enhances(&self) -> Result<Vec<Dependency>, RPMError> {
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
    /// if installing it would cause errors, it can be ignored ignored without error.
    pub fn get_supplements(&self) -> Result<Vec<Dependency>, RPMError> {
        self.get_dependencies(
            IndexTag::RPMTAG_SUPPLEMENTNAME,
            IndexTag::RPMTAG_SUPPLEMENTFLAGS,
            IndexTag::RPMTAG_SUPPLEMENTVERSION,
        )
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
                Err(RPMError::TagNotFound(_)),
                Err(RPMError::TagNotFound(_)),
                Err(RPMError::TagNotFound(_)),
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
                                acc.push(PathBuf::from(dir).join(basename));
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
            .get_entry_data_as_u16_array(IndexTag::RPMTAG_FILEMODES);
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
        // @todo
        // let caps = self.get_entry_i32_array_data(IndexTag::RPMTAG_FILECAPS)?;

        match (modes, users, groups, digests, mtimes, sizes, flags) {
            (Ok(modes), Ok(users), Ok(groups), Ok(digests), Ok(mtimes), Ok(sizes), Ok(flags)) => {
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
            (
                Err(RPMError::TagNotFound(_)),
                Err(RPMError::TagNotFound(_)),
                Err(RPMError::TagNotFound(_)),
                Err(RPMError::TagNotFound(_)),
                Err(RPMError::TagNotFound(_)),
                Err(RPMError::TagNotFound(_)),
                Err(RPMError::TagNotFound(_)),
            ) => Ok(vec![]),
            (modes, users, groups, digests, mtimes, sizes, flags) => {
                modes?;
                users?;
                groups?;
                digests?;
                mtimes?;
                sizes?;
                flags?;
                unreachable!()
            }
        }
    }

    /// Return a list of changelog entries
    pub fn get_changelog_entries(&self) -> Result<Vec<ChangelogEntry>, RPMError> {
        let authors = self
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_CHANGELOGNAME);
        let timestamps = self
            .header
            .get_entry_data_as_u32_array(IndexTag::RPMTAG_CHANGELOGTIME);
        let descriptions = self
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_CHANGELOGTEXT);

        // Return an empty list if the tags are not present
        match (authors, timestamps, descriptions) {
            (
                Err(RPMError::TagNotFound(_)),
                Err(RPMError::TagNotFound(_)),
                Err(RPMError::TagNotFound(_)),
            ) => Ok(vec![]),
            (Ok(authors), Ok(timestamps), Ok(descriptions)) => {
                let v = Vec::from_iter(
                    itertools::multizip((authors, timestamps, descriptions)).map(
                        |(author, timestamp, description)| ChangelogEntry {
                            author: author.to_owned(),
                            timestamp: timestamp as u64,
                            description: description.to_owned(),
                        },
                    ),
                );
                Ok(v)
            }
            (author, timestamp, description) => {
                author?;
                timestamp?;
                description?;
                unreachable!()
            }
        }
    }
}
