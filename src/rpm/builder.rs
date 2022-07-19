use std::collections::{BTreeMap, BTreeSet};

use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use crate::errors::*;

use super::compressor::Compressor;
use super::headers::*;
use super::Lead;
use crate::constants::*;

#[cfg(feature = "signature-meta")]
use crate::sequential_cursor::SeqCursor;
#[cfg(feature = "signature-meta")]
use crate::signature;

use crate::RPMPackage;
use crate::RPMPackageMetadata;

#[cfg(feature = "async-tokio")]
use tokio::io::AsyncReadExt;

#[cfg(unix)]
fn file_mode(file: &std::fs::File) -> Result<u32, RPMError> {
    Ok(file.metadata()?.permissions().mode())
}

#[cfg(windows)]
fn file_mode(_file: &std::fs::File) -> Result<u32, RPMError> {
    Ok(0)
}

#[cfg(all(unix, feature = "async-tokio"))]
async fn tokio_file_mode(file: &tokio::fs::File) -> Result<u32, RPMError> {
    Ok(file.metadata().await?.permissions().mode())
}

#[cfg(all(windows, feature = "async-tokio"))]
async fn tokio_file_mode(_file: &tokio::fs::File) -> Result<u32, RPMError> {
    Ok(0)
}

/// Builder pattern for a full rpm file.
///
/// Prefered method of creating a rpm file.
pub struct RPMBuilder {
    name: String,
    epoch: i32,
    version: String,
    license: String,
    arch: String,
    uid: Option<u32>,
    gid: Option<u32>,
    desc: String,
    release: String,

    // File entries need to be sorted. The entries need to be in the same order as they come
    // in the cpio payload. Otherwise rpm will not be able to resolve those paths.
    // key is the directory, values are complete paths
    files: BTreeMap<String, RPMFileEntry>,
    directories: BTreeSet<String>,
    requires: Vec<Dependency>,
    obsoletes: Vec<Dependency>,
    provides: Vec<Dependency>,
    conflicts: Vec<Dependency>,

    pre_inst_script: Option<String>,
    post_inst_script: Option<String>,
    pre_uninst_script: Option<String>,
    post_uninst_script: Option<String>,

    changelog_authors: Vec<String>,
    changelog_entries: Vec<String>,
    changelog_times: Vec<i32>,
    compressor: Compressor,
}

impl RPMBuilder {
    pub fn new(name: &str, version: &str, license: &str, arch: &str, desc: &str) -> Self {
        RPMBuilder {
            name: name.to_string(),
            epoch: 0,
            version: version.to_string(),
            license: license.to_string(),
            arch: arch.to_string(),
            desc: desc.to_string(),
            release: "1".to_string(),
            uid: None,
            gid: None,
            conflicts: Vec::new(),
            provides: Vec::new(),
            obsoletes: Vec::new(),
            requires: Vec::new(),
            pre_inst_script: None,
            post_inst_script: None,
            pre_uninst_script: None,
            post_uninst_script: None,
            files: BTreeMap::new(),
            changelog_authors: Vec::new(),
            changelog_entries: Vec::new(),
            changelog_times: Vec::new(),
            compressor: Compressor::None(Vec::new()),
            directories: BTreeSet::new(),
        }
    }

    pub fn epoch(mut self, epoch: i32) -> Self {
        self.epoch = epoch;
        self
    }

    pub fn compression(mut self, comp: Compressor) -> Self {
        self.compressor = comp;
        self
    }

    pub fn add_changelog_entry<E, F>(mut self, author: E, entry: F, time: i32) -> Self
    where
        E: Into<String>,
        F: Into<String>,
    {
        self.changelog_authors.push(author.into());
        self.changelog_entries.push(entry.into());
        self.changelog_times.push(time);
        self
    }

    #[cfg(feature = "async-tokio")]
    pub async fn with_file_async<T, P>(mut self, source: P, options: T) -> Result<Self, RPMError>
    where
        P: AsRef<Path>,
        T: Into<RPMFileOptions>,
    {
        let mut input = tokio::fs::File::open(source).await?;
        let mut content = Vec::new();
        input.read_to_end(&mut content).await?;
        let mut options = options.into();
        if options.inherit_permissions {
            options.mode = (tokio_file_mode(&input).await? as i32).into();
        }
        self.add_data(
            content,
            input
                .metadata()
                .await?
                .modified()?
                .duration_since(UNIX_EPOCH)
                .expect("something really wrong with your time")
                .as_secs() as i32,
            options,
        )?;
        Ok(self)
    }

    pub fn with_file<T, P>(mut self, source: P, options: T) -> Result<Self, RPMError>
    where
        P: AsRef<Path>,
        T: Into<RPMFileOptions>,
    {
        let mut input = std::fs::File::open(source)?;
        let mut content = Vec::new();
        input.read_to_end(&mut content)?;
        let mut options = options.into();
        if options.inherit_permissions {
            options.mode = (file_mode(&input)? as i32).into();
        }
        self.add_data(
            content,
            input
                .metadata()?
                .modified()?
                .duration_since(UNIX_EPOCH)
                .expect("something really wrong with your time")
                .as_secs() as i32,
            options,
        )?;
        Ok(self)
    }

    fn add_data(
        &mut self,
        content: Vec<u8>,
        modified_at: i32,
        options: RPMFileOptions,
    ) -> Result<(), RPMError> {
        use sha2::Digest;

        let dest = options.destination;
        if !dest.starts_with("./") && !dest.starts_with('/') {
            return Err(RPMError::InvalidDestinationPath {
                path: dest,
                desc: "invalid start, expected / or ./",
            });
        }

        let pb = PathBuf::from(dest.clone());

        let parent = pb
            .parent()
            .ok_or_else(|| RPMError::InvalidDestinationPath {
                path: dest.clone(),
                desc: "no parent directory found",
            })?;
        let (cpio_path, dir) = if dest.starts_with('.') {
            (
                dest.to_string(),
                format!("/{}/", parent.strip_prefix(".").unwrap().to_string_lossy()),
            )
        } else {
            (
                format!(".{}", dest),
                format!("{}/", parent.to_string_lossy()),
            )
        };

        let mut hasher = sha2::Sha256::default();
        hasher.update(&content);
        let hash_result = hasher.finalize();
        let sha_checksum = hex::encode(hash_result); // encode as string
        let entry = RPMFileEntry {
            base_name: pb.file_name().unwrap().to_string_lossy().to_string(),
            size: content.len() as i32,
            content: Some(content),
            flag: options.flag,
            user: options.user,
            group: options.group,
            mode: options.mode,
            link: options.symlink,
            modified_at,
            dir: dir.clone(),
            sha_checksum,
        };

        self.directories.insert(dir);
        self.files.entry(cpio_path).or_insert(entry);
        Ok(())
    }

    pub fn pre_install_script<T: Into<String>>(mut self, content: T) -> Self {
        self.pre_inst_script = Some(content.into());
        self
    }

    pub fn post_install_script<T: Into<String>>(mut self, content: T) -> Self {
        self.post_inst_script = Some(content.into());
        self
    }

    pub fn pre_uninstall_script<T: Into<String>>(mut self, content: T) -> Self {
        self.pre_uninst_script = Some(content.into());
        self
    }

    pub fn post_uninstall_script<T: Into<String>>(mut self, content: T) -> Self {
        self.post_uninst_script = Some(content.into());
        self
    }

    pub fn release<T: ToString>(mut self, release: T) -> Self {
        self.release = release.to_string();
        self
    }

    pub fn requires(mut self, dep: Dependency) -> Self {
        self.requires.push(dep);
        self
    }

    pub fn obsoletes(mut self, dep: Dependency) -> Self {
        self.obsoletes.push(dep);
        self
    }

    pub fn conflicts(mut self, dep: Dependency) -> Self {
        self.conflicts.push(dep);
        self
    }

    pub fn provides(mut self, dep: Dependency) -> Self {
        self.provides.push(dep);
        self
    }

    /// build without a signature
    ///
    /// ignores a present key, if any
    pub fn build(self) -> Result<RPMPackage, RPMError> {
        let (lead, header_idx_tag, content) = self.prepare_data()?;

        let mut header = Vec::with_capacity(128);
        header_idx_tag.write(&mut header)?;
        let header = header;

        let (header_digest_sha1, header_and_content_digest_md5) =
            Self::derive_hashes(header.as_slice(), content.as_slice())?;

        let header_and_content_len = header.len() + content.len();

        let digest_header = Header::<IndexSignatureTag>::builder()
            .add_digest(
                header_digest_sha1.as_str(),
                header_and_content_digest_md5.as_slice(),
            )
            .build(header_and_content_len as i32);

        let metadata = RPMPackageMetadata {
            lead,
            signature: digest_header,
            header: header_idx_tag,
        };
        let pkg = RPMPackage { metadata, content };
        Ok(pkg)
    }

    /// use an external signer to sing and build
    ///
    /// See `signature::Signing` for more details.
    #[cfg(feature = "signature-meta")]
    pub fn build_and_sign<S>(self, signer: S) -> Result<RPMPackage, RPMError>
    where
        S: signature::Signing<crate::signature::algorithm::RSA>,
    {
        let (lead, header_idx_tag, content) = self.prepare_data()?;

        let mut header = Vec::with_capacity(128);
        header_idx_tag.write(&mut header)?;
        let header = header;

        let (header_digest_sha1, header_and_content_digest_md5) =
            Self::derive_hashes(header.as_slice(), content.as_slice())?;

        let header_and_content_len = header.len() + content.len();

        let builder = Header::<IndexSignatureTag>::builder().add_digest(
            header_digest_sha1.as_str(),
            header_and_content_digest_md5.as_slice(),
        );

        let signature_header = {
            let rsa_sig_header_only = signer.sign(header.as_slice())?;

            let cursor = SeqCursor::new(&[header.as_slice(), content.as_slice()]);
            let rsa_sig_header_and_archive = signer.sign(cursor)?;

            builder
                .add_signature(
                    rsa_sig_header_only.as_ref(),
                    rsa_sig_header_and_archive.as_ref(),
                )
                .build(header_and_content_len as i32)
        };

        let metadata = RPMPackageMetadata {
            lead,
            signature: signature_header,
            header: header_idx_tag,
        };
        let pkg = RPMPackage { metadata, content };
        Ok(pkg)
    }

    /// use prepared data but make sure the signatures are
    fn derive_hashes(header: &[u8], content: &[u8]) -> Result<(String, Vec<u8>), RPMError> {
        let digest_md5 = {
            use md5::Digest;

            // accross header index and content (compressed or uncompressed, depends on configuration)
            let mut hasher = md5::Md5::default();
            hasher.update(&header);
            hasher.update(&content);
            let digest_md5 = hasher.finalize();
            digest_md5.to_vec()
        };

        // header only, not the lead, just the header index
        let digest_sha1 = {
            use sha1::Digest;

            let mut hasher = sha1::Sha1::default();
            hasher.update(&header);
            let digest_sha1 = hasher.finalize();
            hex::encode(digest_sha1)
        };

        Ok((digest_sha1, digest_md5))
    }

    /// prepapre all rpm headers including content
    ///
    /// @todo split this into multiple `fn`s, one per `IndexTag`-group.
    fn prepare_data(mut self) -> Result<(Lead, Header<IndexTag>, Vec<u8>), RPMError> {
        // signature depends on header and payload. So we build these two first.
        // then the signature. Then we stitch all toghether.
        // Lead is not important. just build it here

        let lead = Lead::new(&self.name);

        let mut ino_index = 1;

        let mut file_sizes = Vec::new();
        let mut file_modes = Vec::new();
        let mut file_rdevs = Vec::new();
        let mut file_mtimes = Vec::new();
        let mut file_hashes = Vec::new();
        let mut file_linktos = Vec::new();
        let mut file_flags = Vec::new();
        let mut file_usernames = Vec::new();
        let mut file_groupnames = Vec::new();
        let mut file_devices = Vec::new();
        let mut file_inodes = Vec::new();
        let mut file_langs = Vec::new();
        let mut file_verify_flags = Vec::new();
        let mut dir_indixes = Vec::new();
        let mut base_names = Vec::new();

        let mut combined_file_sizes = 0;

        for (cpio_path, entry) in self.files.iter() {
            combined_file_sizes += entry.size;
            file_sizes.push(entry.size);
            file_modes.push(entry.mode.into());
            // I really do not know the difference. It seems like file_rdevice is always 0 and file_device number always 1.
            // Who knows, who cares.
            file_rdevs.push(0);
            file_devices.push(1);
            file_mtimes.push(entry.modified_at);
            file_hashes.push(entry.sha_checksum.to_owned());
            file_linktos.push(entry.link.to_owned());
            file_flags.push(entry.flag);
            file_usernames.push(entry.user.to_owned());
            file_groupnames.push(entry.group.to_owned());
            file_inodes.push(ino_index as i32);
            file_langs.push("".to_string());
            let index = self
                .directories
                .iter()
                .position(|d| d == &entry.dir)
                .unwrap();
            dir_indixes.push(index as i32);
            base_names.push(entry.base_name.to_owned());
            file_verify_flags.push(-1);
            let content = entry.content.to_owned().unwrap();
            let mut writer = cpio::newc::Builder::new(cpio_path)
                .mode(entry.mode.into())
                .ino(ino_index as u32)
                .uid(self.uid.unwrap_or(0))
                .gid(self.gid.unwrap_or(0))
                .write(&mut self.compressor, content.len() as u32);

            writer.write_all(&content)?;
            writer.finish()?;

            ino_index += 1;
        }

        self.requires.push(Dependency::any("/bin/sh".to_string()));

        self.provides
            .push(Dependency::eq(self.name.clone(), self.version.clone()));
        self.provides.push(Dependency::eq(
            format!("{}({})", self.name.clone(), self.arch.clone()),
            self.version.clone(),
        ));

        let mut provide_names = Vec::new();
        let mut provide_flags = Vec::new();
        let mut provide_versions = Vec::new();

        for d in self.provides.into_iter() {
            provide_names.push(d.dep_name);
            provide_flags.push(d.sense as i32);
            provide_versions.push(d.version);
        }

        let mut obsolete_names = Vec::new();
        let mut obsolete_flags = Vec::new();
        let mut obsolete_versions = Vec::new();

        for d in self.obsoletes.into_iter() {
            obsolete_names.push(d.dep_name);
            obsolete_flags.push(d.sense as i32);
            obsolete_versions.push(d.version);
        }

        let mut require_names = Vec::new();
        let mut require_flags = Vec::new();
        let mut require_versions = Vec::new();

        for d in self.requires.into_iter() {
            require_names.push(d.dep_name);
            require_flags.push(d.sense as i32);
            require_versions.push(d.version);
        }

        let mut conflicts_names = Vec::new();
        let mut conflicts_flags = Vec::new();
        let mut conflicts_versions = Vec::new();

        for d in self.conflicts.into_iter() {
            conflicts_names.push(d.dep_name);
            conflicts_flags.push(d.sense as i32);
            conflicts_versions.push(d.version);
        }

        let offset = 0;

        let mut actual_records = if self.files.is_empty() {
            // if we have an empty RPM, we have to leave out all file related index entries.
            vec![
                IndexEntry::new(
                    IndexTag::RPMTAG_HEADERI18NTABLE,
                    offset,
                    IndexData::StringTag("C".to_string()),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_NAME,
                    offset,
                    IndexData::StringTag(self.name),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_EPOCH,
                    offset,
                    IndexData::Int32(vec![self.epoch]),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_VERSION,
                    offset,
                    IndexData::StringTag(self.version),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_RELEASE,
                    offset,
                    IndexData::StringTag(self.release),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_DESCRIPTION,
                    offset,
                    IndexData::StringTag(self.desc.clone()),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_SUMMARY,
                    offset,
                    IndexData::StringTag(self.desc),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_SIZE,
                    offset,
                    IndexData::Int32(vec![combined_file_sizes]),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_LICENSE,
                    offset,
                    IndexData::StringTag(self.license),
                ),
                // https://fedoraproject.org/wiki/RPMGroups
                // IndexEntry::new(IndexTag::RPMTAG_GROUP, offset, IndexData::I18NString(group)),
                IndexEntry::new(
                    IndexTag::RPMTAG_OS,
                    offset,
                    IndexData::StringTag("linux".to_string()),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_GROUP,
                    offset,
                    IndexData::I18NString(vec!["Unspecified".to_string()]),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_ARCH,
                    offset,
                    IndexData::StringTag(self.arch),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_PAYLOADFORMAT,
                    offset,
                    IndexData::StringTag("cpio".to_string()),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_PROVIDEVERSION,
                    offset,
                    IndexData::StringArray(provide_versions),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_PROVIDEFLAGS,
                    offset,
                    IndexData::Int32(provide_flags),
                ),
            ]
        } else {
            vec![
                IndexEntry::new(
                    IndexTag::RPMTAG_HEADERI18NTABLE,
                    offset,
                    IndexData::StringTag("C".to_string()),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_NAME,
                    offset,
                    IndexData::StringTag(self.name),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_EPOCH,
                    offset,
                    IndexData::Int32(vec![self.epoch]),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_VERSION,
                    offset,
                    IndexData::StringTag(self.version),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_RELEASE,
                    offset,
                    IndexData::StringTag(self.release),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_DESCRIPTION,
                    offset,
                    IndexData::StringTag(self.desc.clone()),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_SUMMARY,
                    offset,
                    IndexData::StringTag(self.desc),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_SIZE,
                    offset,
                    IndexData::Int32(vec![combined_file_sizes]),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_LICENSE,
                    offset,
                    IndexData::StringTag(self.license),
                ),
                // https://fedoraproject.org/wiki/RPMGroups
                // IndexEntry::new(IndexTag::RPMTAG_GROUP, offset, IndexData::I18NString(group)),
                IndexEntry::new(
                    IndexTag::RPMTAG_OS,
                    offset,
                    IndexData::StringTag("linux".to_string()),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_GROUP,
                    offset,
                    IndexData::I18NString(vec!["Unspecified".to_string()]),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_ARCH,
                    offset,
                    IndexData::StringTag(self.arch),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_PAYLOADFORMAT,
                    offset,
                    IndexData::StringTag("cpio".to_string()),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_FILESIZES,
                    offset,
                    IndexData::Int32(file_sizes),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_FILEMODES,
                    offset,
                    IndexData::Int16(file_modes),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_FILERDEVS,
                    offset,
                    IndexData::Int16(file_rdevs),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_FILEMTIMES,
                    offset,
                    IndexData::Int32(file_mtimes),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_FILEDIGESTS,
                    offset,
                    IndexData::StringArray(file_hashes),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_FILELINKTOS,
                    offset,
                    IndexData::StringArray(file_linktos),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_FILEFLAGS,
                    offset,
                    IndexData::Int32(file_flags),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_FILEUSERNAME,
                    offset,
                    IndexData::StringArray(file_usernames),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_FILEGROUPNAME,
                    offset,
                    IndexData::StringArray(file_groupnames),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_FILEDEVICES,
                    offset,
                    IndexData::Int32(file_devices),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_FILEINODES,
                    offset,
                    IndexData::Int32(file_inodes),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_DIRINDEXES,
                    offset,
                    IndexData::Int32(dir_indixes),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_FILELANGS,
                    offset,
                    IndexData::StringArray(file_langs),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_FILEDIGESTALGO,
                    offset,
                    IndexData::Int32(vec![8]),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_FILEVERIFYFLAGS,
                    offset,
                    IndexData::Int32(file_verify_flags),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_BASENAMES,
                    offset,
                    IndexData::StringArray(base_names),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_DIRNAMES,
                    offset,
                    IndexData::StringArray(self.directories.into_iter().collect()),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_PROVIDENAME,
                    offset,
                    IndexData::StringArray(provide_names),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_PROVIDEVERSION,
                    offset,
                    IndexData::StringArray(provide_versions),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_PROVIDEFLAGS,
                    offset,
                    IndexData::Int32(provide_flags),
                ),
            ]
        };

        let possible_compression_details = self.compressor.get_details();

        if let Some(details) = possible_compression_details {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_PAYLOADCOMPRESSOR,
                offset,
                IndexData::StringTag(details.compression_name.to_string()),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_PAYLOADFLAGS,
                offset,
                IndexData::StringTag(details.compression_level.to_string()),
            ));
        }

        if !self.changelog_authors.is_empty() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_CHANGELOGNAME,
                offset,
                IndexData::StringArray(self.changelog_authors),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_CHANGELOGTEXT,
                offset,
                IndexData::StringArray(self.changelog_entries),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_CHANGELOGTIME,
                offset,
                IndexData::Int32(self.changelog_times),
            ));
        }

        if !obsolete_flags.is_empty() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_OBSOLETENAME,
                offset,
                IndexData::StringArray(obsolete_names),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_OBSOLETEVERSION,
                offset,
                IndexData::StringArray(obsolete_versions),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_OBSOLETEFLAGS,
                offset,
                IndexData::Int32(obsolete_flags),
            ));
        }

        if !require_flags.is_empty() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_REQUIRENAME,
                offset,
                IndexData::StringArray(require_names),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_REQUIREVERSION,
                offset,
                IndexData::StringArray(require_versions),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_REQUIREFLAGS,
                offset,
                IndexData::Int32(require_flags),
            ));
        }

        if !conflicts_flags.is_empty() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_CONFLICTNAME,
                offset,
                IndexData::StringArray(conflicts_names),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_CONFLICTVERSION,
                offset,
                IndexData::StringArray(conflicts_versions),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_CONFLICTFLAGS,
                offset,
                IndexData::Int32(conflicts_flags),
            ));
        }

        if self.pre_inst_script.is_some() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_PREIN,
                offset,
                IndexData::StringTag(self.pre_inst_script.unwrap()),
            ));
        }
        if self.post_inst_script.is_some() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_POSTIN,
                offset,
                IndexData::StringTag(self.post_inst_script.unwrap()),
            ));
        }

        if self.pre_uninst_script.is_some() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_PREUN,
                offset,
                IndexData::StringTag(self.pre_uninst_script.unwrap()),
            ));
        }

        if self.post_uninst_script.is_some() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_POSTUN,
                offset,
                IndexData::StringTag(self.post_uninst_script.unwrap()),
            ));
        }

        let header = Header::from_entries(actual_records, IndexTag::RPMTAG_HEADERIMMUTABLE);

        //those parts seem to break on fedora installations, but it does not seem to matter for centos.
        // if it turns out that those parts are not really required, we will delete the following comments

        // self.requires.push(Dependency::rpm_lib(
        //     "rpmlib(VersionedDependencies)".to_string(),
        //     "3.0.3-1".to_string(),
        // ));

        // self.requires.push(Dependency::rpm_lib(
        //     "rpmlib(PayloadFilesHavePrefix)".to_string(),
        //     "4.0-1".to_string(),
        // ));

        // self.requires.push(Dependency::rpm_lib(
        //     "rpmlib(CompressedFileNames)".to_string(),
        //     "3.0.4-1".to_string(),
        // ));

        // self.requires.push(Dependency::rpm_lib(
        //     "rpmlib(PayloadIsXz)".to_string(),
        //     "5.2-1".to_string(),
        // ));
        // self.requires.push(Dependency::rpm_lib(
        //     "rpmlib(FileDigests)".to_string(),
        //     "4.6.0-1".to_string(),
        // ));

        self.compressor = cpio::newc::trailer(self.compressor)?;
        let content = self.compressor.finish_compression()?;

        Ok((lead, header, content))
    }
}
