//! A collection of types used in various header records.
use crate::{FileCaps, IndexData, IndexEntry, Timestamp, constants::*, errors};
use digest::DynDigest;
use itertools::Itertools;
use sha2::{Sha256, Sha512};
use sha3::Sha3_256;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Cursor};
use std::path::PathBuf;
use std::str::FromStr;
/// Offsets into an RPM Package (from the start of the file) demarking locations of each section
///
/// See: `Package::get_package_segment_offsets`
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PackageSegmentOffsets {
    pub lead: u64,
    pub signature_header: u64,
    pub header: u64,
    pub payload: u64,
}

/// Define rpm content type source, from file path or raw bytes data.
pub enum ContentSource {
    Path(PathBuf),
    Raw(Vec<u8>),
    /// No content - used for directories, symlinks, and ghost files
    None,
}

impl ContentSource {
    /// get type which impl BufRead
    pub fn try_into_bufread(&self) -> io::Result<Box<dyn BufRead + '_>> {
        match self {
            Self::Path(p) => Ok(Box::new(BufReader::new(File::open(p)?))),
            Self::Raw(v) => Ok(Box::new(Cursor::new(v))),
            Self::None => Ok(Box::new(Cursor::new(&[] as &[u8]))),
        }
    }

    pub fn size(&self) -> io::Result<u64> {
        match self {
            Self::Path(p) => fs::metadata(p).map(|m| m.len()),
            Self::Raw(v) => Ok(v.len() as u64),
            Self::None => Ok(0),
        }
    }
}
/// Describes a file present in the rpm file.
pub struct PackageFileEntry {
    pub mode: FileMode,
    pub modified_at: Timestamp,
    pub link: String,
    pub flags: FileFlags,
    pub user: String,
    pub group: String,
    pub base_name: String,
    pub dir: String,
    pub caps: Option<FileCaps>,
    pub verify_flags: FileVerifyFlags,
    pub source: ContentSource,
    /// Whether this entry was added by a bulk operation (e.g. `with_dir_contents`).
    /// Bulk-added entries can be replaced by explicit methods like `with_file`.
    pub(crate) bulk_added: bool,
}

/// The type of a file entry in an RPM package.
#[non_exhaustive]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum FileType {
    Regular,
    Dir,
    SymbolicLink,
    /// A file type not directly handled by this library (e.g. block/char devices, FIFOs, sockets).
    Other,
}

/// A file mode combining file type and permission bits, as stored in RPM headers.
///
/// See <https://man7.org/linux/man-pages/man7/inode.7.html> section "The file type and mode"
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub struct FileMode(u16);

const FILE_TYPE_BIT_MASK: u16 = 0o170000; // bit representation = "1111000000000000"
const PERMISSIONS_BIT_MASK: u16 = 0o7777; // bit representation = "0000111111111111"
pub const REGULAR_FILE_TYPE: u16 = 0o100000; //  bit representation = "1000000000000000"
pub const DIR_FILE_TYPE: u16 = 0o040000; //      bit representation = "0100000000000000"
pub const SYMBOLIC_LINK_FILE_TYPE: u16 = 0o120000; // bit representation = "1010000000000000"

impl From<u16> for FileMode {
    fn from(raw_mode: u16) -> Self {
        FileMode(raw_mode)
    }
}

impl TryFrom<i32> for FileMode {
    type Error = errors::Error;

    fn try_from(raw_mode: i32) -> Result<Self, Self::Error> {
        if raw_mode > u16::MAX.into() || raw_mode < i16::MIN.into() {
            Err(errors::Error::InvalidFileMode {
                raw_mode,
                reason: "provided integer is out of 16bit bounds",
            })
        } else {
            Ok(FileMode(raw_mode as u16))
        }
    }
}

impl FileMode {
    /// Create a regular file mode. `permissions` will be masked to 0o7777.
    pub fn regular(permissions: u16) -> Self {
        FileMode(REGULAR_FILE_TYPE | (permissions & PERMISSIONS_BIT_MASK))
    }

    /// Create a directory mode. `permissions` will be masked to 0o7777.
    pub fn dir(permissions: u16) -> Self {
        FileMode(DIR_FILE_TYPE | (permissions & PERMISSIONS_BIT_MASK))
    }

    /// Create a symbolic link mode. `permissions` will be masked to 0o7777.
    pub fn symbolic_link(permissions: u16) -> Self {
        FileMode(SYMBOLIC_LINK_FILE_TYPE | (permissions & PERMISSIONS_BIT_MASK))
    }

    /// Set the permission bits, preserving the file type. Values greater than 0o7777 will be masked.
    pub fn set_permissions(&mut self, permissions: u16) {
        self.0 = self.raw_file_type() | (permissions & PERMISSIONS_BIT_MASK);
    }

    /// Returns the complete raw mode (type + permissions bits).
    pub fn raw_mode(&self) -> u16 {
        self.0
    }

    /// Returns the [`FileType`] of this mode.
    pub fn file_type(&self) -> FileType {
        match self.0 & FILE_TYPE_BIT_MASK {
            DIR_FILE_TYPE => FileType::Dir,
            REGULAR_FILE_TYPE => FileType::Regular,
            SYMBOLIC_LINK_FILE_TYPE => FileType::SymbolicLink,
            _ => FileType::Other,
        }
    }

    /// Returns the raw file type bits from the mode.
    pub fn raw_file_type(&self) -> u16 {
        self.0 & FILE_TYPE_BIT_MASK
    }

    /// Returns the permission bits (including setuid/setgid/sticky).
    pub fn permissions(&self) -> u16 {
        self.0 & PERMISSIONS_BIT_MASK
    }
}

impl From<FileMode> for u32 {
    fn from(mode: FileMode) -> Self {
        mode.raw_mode() as u32
    }
}

impl From<FileMode> for u16 {
    fn from(mode: FileMode) -> Self {
        mode.raw_mode()
    }
}

#[derive(Debug)]
pub struct FileOptions {
    pub(crate) destination: String,
    /// `None` means use the builder's default user.
    pub(crate) user: Option<String>,
    /// `None` means use the builder's default group.
    pub(crate) group: Option<String>,
    pub(crate) symlink: String,
    pub(crate) mode: FileMode,
    pub(crate) flag: FileFlags,
    pub(crate) use_default_permissions: bool,
    pub(crate) caps: Option<FileCaps>,
    pub(crate) verify_flags: FileVerifyFlags,
}

impl FileOptions {
    /// Create a new FileOptions for a regular file which will be placed at the provided path.
    ///
    /// By default, files will be owned by the "root" user and group, and inherit their permissions
    /// from the on-disk file.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(dest: impl Into<String>) -> FileOptionsBuilder {
        FileOptionsBuilder {
            inner: FileOptions {
                destination: dest.into(),
                user: None,
                group: None,
                symlink: "".to_string(),
                mode: FileMode::regular(0o664),
                flag: FileFlags::empty(),
                use_default_permissions: true,
                caps: None,
                verify_flags: FileVerifyFlags::all(),
            },
        }
    }

    /// Create a new FileOptions for a directory at the provided path.
    ///
    /// Directories do not require any content source. Use with
    /// [`PackageBuilder::with_dir()`] to add a directory entry.
    ///
    /// Default permissions are 0o755.
    pub fn dir(dest: impl Into<String>) -> FileOptionsBuilder {
        FileOptionsBuilder {
            inner: FileOptions {
                destination: dest.into(),
                user: None,
                group: None,
                symlink: "".to_string(),
                mode: FileMode::dir(0o755),
                flag: FileFlags::empty(),
                use_default_permissions: true,
                caps: None,
                verify_flags: FileVerifyFlags::all(),
            },
        }
    }

    /// Create a new FileOptions for a symbolic link.
    ///
    /// `dest` is the path where the symlink will be created.
    /// `target` is the path the symlink points to.
    ///
    /// Symlinks do not require any content source. Use with
    /// [`PackageBuilder::with_file_contents()`] (passing empty content) or
    /// [`PackageBuilder::with_symlink()`].
    pub fn symlink(dest: impl Into<String>, target: impl Into<String>) -> FileOptionsBuilder {
        FileOptionsBuilder {
            inner: FileOptions {
                destination: dest.into(),
                user: None,
                group: None,
                symlink: target.into(),
                mode: FileMode::symbolic_link(0o777),
                flag: FileFlags::empty(),
                use_default_permissions: false,
                caps: None,
                verify_flags: FileVerifyFlags::all(),
            },
        }
    }

    /// Create a new FileOptions for a ghost file at the provided path.
    ///
    /// Ghost files are not included in the package payload, but their metadata
    /// (ownership, permissions, etc.) is tracked by RPM. This is commonly used
    /// for files that are created at runtime, such as log files or PID files.
    ///
    /// Use with [`PackageBuilder::with_ghost()`].
    ///
    /// Default permissions are 0o644.
    pub fn ghost(dest: impl Into<String>) -> FileOptionsBuilder {
        FileOptionsBuilder {
            inner: FileOptions {
                destination: dest.into(),
                user: None,
                group: None,
                symlink: "".to_string(),
                mode: FileMode::regular(0o644),
                flag: FileFlags::GHOST,
                use_default_permissions: true,
                caps: None,
                verify_flags: FileVerifyFlags::all(),
            },
        }
    }

    /// Create a new FileOptions for a ghost directory at the provided path.
    ///
    /// Like ghost files, ghost directories are not included in the package payload,
    /// but their metadata is tracked by RPM.
    ///
    /// Use with [`PackageBuilder::with_ghost()`].
    ///
    /// Default permissions are 0o755.
    pub fn ghost_dir(dest: impl Into<String>) -> FileOptionsBuilder {
        FileOptionsBuilder {
            inner: FileOptions {
                destination: dest.into(),
                user: None,
                group: None,
                symlink: "".to_string(),
                mode: FileMode::dir(0o755),
                flag: FileFlags::GHOST,
                use_default_permissions: true,
                caps: None,
                verify_flags: FileVerifyFlags::all(),
            },
        }
    }
}

#[derive(Debug)]
pub struct FileOptionsBuilder {
    inner: FileOptions,
}

impl FileOptionsBuilder {
    /// Indicates that the file should be owned by the specified username.
    ///
    /// Specifying a non-root user here will direct RPM to create the user via sysusers.d at
    /// installation time.
    ///
    /// See: `%attr` from specfile syntax
    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.inner.user = Some(user.into());
        self
    }

    /// Indicates that the file should be part of the specified group.
    ///
    /// Specifying a non-root group here will direct RPM to create the group via sysusers.d at
    /// installation time.
    ///
    /// See: `%attr` from specfile syntax
    pub fn group(mut self, group: impl Into<String>) -> Self {
        self.inner.group = Some(group.into());
        self
    }

    /// Indicates that a file is a symlink pointing to the location provided
    pub fn symlink(mut self, symlink: impl Into<String>) -> Self {
        self.inner.symlink = symlink.into();
        self
    }

    /// Set the FileMode - type of file (or directory, or symlink) and permissions.
    ///
    /// Note: prefer using [`permissions()`](Self::permissions) instead, which sets only the
    /// permission bits without requiring the file type prefix. This method requires the caller
    /// to include the file type in the mode value (e.g. `0o100755` for a regular file with
    /// `rwxr-xr-x` permissions).
    ///
    /// See: `%attr` from specfile syntax
    pub fn mode(mut self, mode: impl Into<FileMode>) -> Self {
        self.inner.mode = mode.into();
        self.inner.use_default_permissions = false;
        self
    }

    /// Set the permission bits for the file without changing the file type.
    ///
    /// This is the preferred way to set permissions. Unlike [`mode()`](Self::mode), you only
    /// need to provide the permission bits (e.g. `0o755`) without the file type prefix.
    ///
    /// Values greater than `0o7777` will be masked to fit.
    ///
    /// See: `%attr` from specfile syntax
    pub fn permissions(mut self, permissions: u16) -> Self {
        self.inner.mode.set_permissions(permissions);
        self.inner.use_default_permissions = false;
        self
    }

    /// Indicates that a file should have the provided POSIX file capabilities.
    ///
    /// See: `%caps` from specfile syntax
    pub fn caps(mut self, caps: impl Into<String>) -> Result<Self, errors::Error> {
        // verify capabilities
        self.inner.caps = match FileCaps::from_str(&caps.into()) {
            Ok(caps) => Some(caps),
            Err(e) => {
                return Err(errors::Error::InvalidCapabilities {
                    caps: e.to_string(),
                });
            }
        };
        Ok(self)
    }

    /// Direct which aspects of the file you would like RPM to verify.
    ///
    /// By default, every aspect of the file will be checked.
    ///
    /// See: `%verify` from specfile syntax
    pub fn verify(mut self, flags: FileVerifyFlags) -> Self {
        self.inner.verify_flags = flags;
        self
    }

    /// Indicates that a file is documentation.
    ///
    /// See: `%doc` from specfile syntax
    pub fn doc(mut self) -> Self {
        self.inner.flag.insert(FileFlags::DOC);
        self
    }

    /// Mark this file as a configuration file. When a package is updated, files marked as
    /// configuration files will be checked for modifications compared to their default state,
    /// and if any are present then the old configuration file will be saved with a `.rpmsave`
    /// extension.
    ///
    /// User intervention may be required to reconcile the changes between the new and old configs.
    ///
    /// Can be combined with [`noreplace()`](Self::noreplace) or [`missingok()`](Self::missingok).
    ///
    /// See: `%config` from specfile syntax
    pub fn config(mut self) -> Self {
        self.inner.flag.insert(FileFlags::CONFIG);
        self
    }

    /// Indicates that a configuration file should not be replaced if it has been modified.
    /// When a package is updated, the new configuration file will be installed with a `.rpmnew`
    /// extension instead.
    ///
    /// User intervention may be required to reconcile the changes between the new and old configs.
    ///
    /// Only meaningful in combination with [`config()`](Self::config).
    ///
    /// See: `%config(noreplace)` from specfile syntax
    pub fn noreplace(mut self) -> Self {
        self.inner.flag.insert(FileFlags::NOREPLACE);
        self
    }

    /// Indicates that the absence of this file is not an error. During verification (`rpm -V`),
    /// a missing file marked with `missingok` will not be reported as a failure. During package
    /// removal, the file will be silently skipped if it does not exist.
    ///
    /// This is an independent attribute — it can be set on any file, not just config files.
    /// However, it is commonly combined with [`config()`](Self::config).
    ///
    /// See: `%missingok` or `%config(missingok)` from specfile syntax
    pub fn missingok(mut self) -> Self {
        self.inner.flag.insert(FileFlags::MISSINGOK);
        self
    }

    /// Indicates that a file ought not to actually be included in the package, but that it should
    /// still be considered owned by a package (e.g. a log file). Its attributes are still tracked.
    ///
    /// Note: prefer using [`FileOptions::ghost()`] / [`PackageBuilder::with_ghost()`] instead of
    /// setting this flag manually, as those constructors handle the content source correctly.
    ///
    /// See: `%ghost` from specfile syntax
    pub fn ghost(mut self) -> Self {
        self.inner.flag.insert(FileFlags::GHOST);
        self
    }

    /// Mark this file as a software license. License files are always included — they are
    /// never filtered out during installation.
    ///
    /// See: `%license` from specfile syntax
    pub fn license(mut self) -> Self {
        self.inner.flag.insert(FileFlags::LICENSE);
        self
    }

    /// Mark this file as a build artifact.
    ///
    /// See: `%artifact` from specfile syntax
    pub fn artifact(mut self) -> Self {
        self.inner.flag.insert(FileFlags::ARTIFACT);
        self
    }

    /// Deprecated: use [`doc()`](Self::doc) instead. Marks a file as a README.
    ///
    /// See: `%readme` from specfile syntax
    #[deprecated(since = "0.20.0", note = "use doc() instead")]
    pub fn readme(mut self) -> Self {
        self.inner.flag.insert(FileFlags::README);
        self
    }
}

impl From<FileOptionsBuilder> for FileOptions {
    fn from(builder: FileOptionsBuilder) -> Self {
        builder.inner
    }
}

/// Description of a dependency as present in a RPM header record.
#[derive(Debug, PartialEq, Eq)]
pub struct Dependency {
    pub name: String,
    pub flags: DependencyFlags,
    pub version: String,
}

impl Dependency {
    /// Create a dependency on any version of some package or file (or string in general).
    pub fn any(dep_name: impl Into<String>) -> Self {
        Self::new(dep_name.into(), DependencyFlags::ANY, "".to_string())
    }

    /// Create a dependency on an exact version of some package.
    pub fn eq(dep_name: impl Into<String>, version: impl Into<String>) -> Self {
        Self::new(dep_name.into(), DependencyFlags::EQUAL, version.into())
    }

    /// Create a dependency on a version of some package less than the provided one.
    pub fn less(dep_name: impl Into<String>, version: impl Into<String>) -> Self {
        Self::new(dep_name.into(), DependencyFlags::LESS, version.into())
    }

    /// Create a dependency on a version of some package less than or equal to the provided one.
    pub fn less_eq(dep_name: impl Into<String>, version: impl Into<String>) -> Self {
        Self::new(
            dep_name.into(),
            DependencyFlags::LESS | DependencyFlags::EQUAL,
            version.into(),
        )
    }

    /// Create a dependency on a version of some package greater than the provided one.
    pub fn greater(dep_name: impl Into<String>, version: impl Into<String>) -> Self {
        Self::new(dep_name.into(), DependencyFlags::GREATER, version.into())
    }

    /// Create a dependency on a version of some package greater than or equal to the provided one.
    pub fn greater_eq(dep_name: impl Into<String>, version: impl Into<String>) -> Self {
        Self::new(
            dep_name.into(),
            DependencyFlags::GREATER | DependencyFlags::EQUAL,
            version.into(),
        )
    }

    /// Create a dependency on an rpm feature, required to install this package
    pub fn rpmlib(dep_name: impl Into<String>, version: impl Into<String>) -> Self {
        Self::new(
            format!("rpmlib({})", dep_name.into()),
            DependencyFlags::RPMLIB | DependencyFlags::EQUAL,
            version.into(),
        )
    }

    /// Add a config dependency
    pub fn config(dep_name: &str, version: impl Into<String>) -> Self {
        Self::new(
            format!("config({})", dep_name),
            DependencyFlags::CONFIG | DependencyFlags::EQUAL,
            version.into(),
        )
    }

    /// Create a new user dependency
    ///
    /// If such a dependency is required, versions of RPM 4.19 and newer will automatically create
    /// the required users and groups using systemd sys.users.d.
    pub fn user(username: &str) -> Self {
        Self::new(
            format!("user({})", username),
            DependencyFlags::SCRIPT_PRE | DependencyFlags::SCRIPT_POSTUN,
            "".to_owned(),
        )
    }

    /// Create a new group dependency
    ///
    /// If such a dependency is required, versions of RPM 4.19 and newer will automatically create
    /// the required users and groups using systemd sys.users.d.
    pub fn group(groupname: &str) -> Self {
        Self::new(
            format!("group({})", groupname),
            DependencyFlags::SCRIPT_PRE | DependencyFlags::SCRIPT_POSTUN,
            "".to_owned(),
        )
    }

    // @todo: Is it ever the case that version matters here? it's at least not the common case

    /// Create a dependency on a package or file required for a pre-install script.
    pub fn script_pre(dep_name: impl Into<String>) -> Self {
        Self::new(dep_name.into(), DependencyFlags::SCRIPT_PRE, "".to_string())
    }

    /// Create a dependency on a package or file required for a post-install script.
    pub fn script_post(dep_name: impl Into<String>) -> Self {
        Self::new(
            dep_name.into(),
            DependencyFlags::SCRIPT_POST,
            "".to_string(),
        )
    }

    /// Create a dependency on a package or file required for a pre-un-install script.
    pub fn script_preun(dep_name: impl Into<String>) -> Self {
        Self::new(
            dep_name.into(),
            DependencyFlags::SCRIPT_PREUN,
            "".to_string(),
        )
    }

    /// Create a dependency on a package or file required for a post-un-install script.
    pub fn script_postun(dep_name: impl Into<String>) -> Self {
        Self::new(
            dep_name.into(),
            DependencyFlags::SCRIPT_POSTUN,
            "".to_string(),
        )
    }

    fn new(dep_name: String, flags: DependencyFlags, version: String) -> Self {
        Dependency {
            name: dep_name,
            flags,
            version,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum HashKind {
    Sha256,
    Sha512,
    Sha3_256,
}

impl HashKind {
    fn build(self) -> Box<dyn DynDigest> {
        match self {
            Self::Sha256 => Box::new(Sha256::default()),
            Self::Sha512 => Box::new(Sha512::default()),
            Self::Sha3_256 => Box::new(Sha3_256::default()),
        }
    }
}
/// A wrapper for calculating the sha256 checksum of the contents written to it
pub struct ChecksummingWriter<W> {
    writer: W,
    engines: HashMap<HashKind, Box<dyn DynDigest>>,
    bytes_written: usize,
}

impl<W> ChecksummingWriter<W> {
    pub fn new(writer: W, kinds: &[HashKind]) -> Self {
        Self {
            writer,
            engines: kinds
                .iter()
                .map(|&k| (k, k.build()))
                .collect::<HashMap<_, _>>(),
            bytes_written: 0,
        }
    }

    pub fn into_digests(self) -> (HashMap<HashKind, String>, usize) {
        let map = self
            .engines
            .into_iter()
            .map(|(k, e)| (k, hex::encode(e.finalize())))
            .collect();
        (map, self.bytes_written)
    }
}

impl<W: std::io::Write> std::io::Write for ChecksummingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        for eng in self.engines.values_mut() {
            eng.update(buf);
        }
        self.bytes_written += buf.len();
        self.writer.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

/// Type-alias for a tuple containing index tags for a scriptlet type,
pub(crate) type ScriptletIndexTags = (IndexTag, IndexTag, IndexTag);

/// Description of a scriptlet as present in a RPM header record
pub struct Scriptlet {
    /// Content of the scriptlet
    pub script: String,
    /// Optional scriptlet flags
    pub flags: Option<ScriptletFlags>,
    /// Optional scriptlet interpreter/arguments
    pub program: Option<Vec<String>>,
}

impl Scriptlet {
    /// Returns a new scriplet
    #[inline]
    pub fn new(script: impl Into<String>) -> Scriptlet {
        Scriptlet {
            script: script.into(),
            flags: None,
            program: None,
        }
    }

    /// Sets the scriptlet flags
    ///
    /// **Note** These flags can be used to configure macro expansions etc.
    #[inline]
    pub fn flags(mut self, flags: ScriptletFlags) -> Self {
        self.flags = Some(flags);
        self
    }

    /// Sets the scriptlet interpreter/arguments
    #[inline]
    pub fn prog(mut self, mut prog: Vec<impl Into<String>>) -> Self {
        self.program = Some(prog.drain(..).map(|p| p.into()).collect_vec());
        self
    }

    /// Consumes the receiver and applies all index entries for the scriptlet based on builder state
    pub(crate) fn apply(self, records: &mut Vec<IndexEntry<IndexTag>>, tags: ScriptletIndexTags) {
        let (script_tag, flags_tag, prog_tag) = tags;

        records.push(IndexEntry::new(
            script_tag,
            IndexData::StringTag(self.script),
        ));

        if let Some(flags) = self.flags {
            records.push(IndexEntry::new(
                flags_tag,
                IndexData::Int32(vec![flags.bits()]),
            ));
        }

        if let Some(prog) = self.program {
            records.push(IndexEntry::new(prog_tag, IndexData::StringArray(prog)));
        }
    }
}

impl<T> From<T> for Scriptlet
where
    T: Into<String>,
{
    fn from(value: T) -> Self {
        Scriptlet::new(value)
    }
}

mod test {
    #[test]
    fn test_file_mode() -> Result<(), Box<dyn std::error::Error>> {
        use super::*;

        // test constructor functions
        let test_table = vec![(0, 0), (0o7777, 0o7777), (0o17777, 0o7777)];
        for (permissions, expected) in test_table {
            let result = FileMode::dir(permissions);
            assert_eq!(expected, result.permissions());
            let result = FileMode::regular(permissions);
            assert_eq!(expected, result.permissions());
            let result = FileMode::symbolic_link(permissions);
            assert_eq!(expected, result.permissions());
        }

        // test set_permissions
        let mut mode = FileMode::regular(0o644);
        assert_eq!(mode.permissions(), 0o644);
        assert_eq!(mode.file_type(), FileType::Regular);

        mode.set_permissions(0o755);
        assert_eq!(mode.permissions(), 0o755);
        assert_eq!(mode.file_type(), FileType::Regular);

        // set_permissions on a directory preserves the directory type
        let mut dir_mode = FileMode::dir(0o755);
        dir_mode.set_permissions(0o700);
        assert_eq!(dir_mode.permissions(), 0o700);
        assert_eq!(dir_mode.file_type(), FileType::Dir);

        // set_permissions masks values > 0o7777
        let mut mode2 = FileMode::regular(0o644);
        mode2.set_permissions(0o17777);
        assert_eq!(mode2.permissions(), 0o7777);
        assert_eq!(mode2.file_type(), FileType::Regular);

        // test TryFrom<i32>
        let try_from_table: Vec<(i32, Result<FileMode, &str>)> = vec![
            (0o10_0664, Ok(FileMode::regular(0o664))),
            (0o04_0665, Ok(FileMode::dir(0o665))),
            // test sticky bit
            (0o10_1664, Ok(FileMode::regular(0o1664))),
            (0o12_0664, Ok(FileMode::symbolic_link(0o0664))),
            (0o12_1664, Ok(FileMode::symbolic_link(0o1664))),
            // unknown file type maps to Other
            (0o664, Ok(FileMode(0o664))),
            // out of 16bit bounds is an error
            (0o27_1664, Err("provided integer is out of 16bit bounds")),
        ];
        for (raw_mode, expected) in try_from_table {
            let result = FileMode::try_from(raw_mode);
            match (&expected, &result) {
                (Ok(expected), Ok(actual)) => assert_eq!(expected, actual),
                (Err(expected_reason), Err(errors::Error::InvalidFileMode { reason, .. })) => {
                    assert_eq!(expected_reason, reason);
                }
                _ => panic!(
                    "mismatched result for {:#o}: expected {:?}, got {:?}",
                    raw_mode, expected, result
                ),
            }
        }

        // test From<u16> and file_type()
        let from_table: Vec<(i32, FileMode, FileType)> = vec![
            (0o10_0755, FileMode::regular(0o0755), FileType::Regular),
            (0o10_1755, FileMode::regular(0o1755), FileType::Regular),
            (0o04_0755, FileMode::dir(0o0755), FileType::Dir),
            (
                0o12_0755,
                FileMode::symbolic_link(0o0755),
                FileType::SymbolicLink,
            ),
            (
                0o12_1755,
                FileMode::symbolic_link(0o1755),
                FileType::SymbolicLink,
            ),
            // unknown file type via From<u16>
            (0o0755, FileMode(0o0755), FileType::Other),
        ];
        for (raw_mode, expected_mode, expected_type) in from_table {
            let mode = FileMode::from(raw_mode as u16);
            assert_eq!(expected_mode, mode);
            assert_eq!(raw_mode as u16, mode.raw_mode());
            assert_eq!(expected_type, mode.file_type());
        }
        Ok(())
    }

    #[test]
    fn test_verify_capabilities_valid() {
        let blank_file = crate::FileOptions::new("/usr/bin/awesome");
        blank_file.caps("cap_net_admin,cap_net_raw+p").unwrap();
    }

    #[test]
    fn test_verify_capabilities_invalid() -> Result<(), crate::errors::Error> {
        let blank_file = crate::FileOptions::new("/usr/bin/awesome");
        blank_file.caps("cap_net_an,cap_net_raw+p").unwrap_err();
        Ok(())
    }

    #[test]
    fn test_scriptlet_builder() {
        // Test full state
        let scriptlet = crate::Scriptlet::new(
            r#"
echo `hello world`
        "#
            .trim(),
        )
        .flags(crate::ScriptletFlags::EXPAND)
        .prog(vec!["/usr/bin/blah", "-c"]);

        let mut records = vec![];

        scriptlet.apply(&mut records, crate::PREIN_TAGS);

        assert!(records.len() == 3);
        assert_eq!(records[0].tag, crate::IndexTag::RPMTAG_PREIN as u32);
        assert_eq!(
            records[0].data,
            crate::IndexData::StringTag("echo `hello world`".to_string())
        );
        assert_eq!(records[1].tag, crate::IndexTag::RPMTAG_PREINFLAGS as u32);
        assert_eq!(records[1].data, crate::IndexData::Int32(vec![1]));
        assert_eq!(records[2].tag, crate::IndexTag::RPMTAG_PREINPROG as u32);
        assert_eq!(
            records[2].data,
            crate::IndexData::StringArray(vec!["/usr/bin/blah".to_string(), "-c".to_string()])
        );

        // Test partial state
        let scriptlet = crate::Scriptlet::new(
            r#"
        echo `hello world`
                "#
            .trim(),
        );

        let mut records = vec![];

        scriptlet.apply(&mut records, crate::POSTUN_TAGS);
        assert!(records.len() == 1);
        assert_eq!(records[0].tag, crate::IndexTag::RPMTAG_POSTUN as u32);
        assert_eq!(
            records[0].data,
            crate::IndexData::StringTag("echo `hello world`".to_string())
        );
    }

    mod checksumming_writer {
        #[test]
        fn test_checksumming_writer_empty() {
            let mut buf: Vec<u8> = Vec::new();
            let writer = crate::ChecksummingWriter::new(
                &mut buf,
                &[
                    crate::HashKind::Sha256,
                    crate::HashKind::Sha512,
                    crate::HashKind::Sha3_256,
                ],
            );
            let (hash_values, len) = writer.into_digests();
            assert!(buf.is_empty());
            for kind in [
                crate::HashKind::Sha256,
                crate::HashKind::Sha512,
                crate::HashKind::Sha3_256,
            ] {
                if let Some(digest) = hash_values.get(&kind) {
                    match kind {
                        crate::HashKind::Sha256 => assert_eq!(
                            digest,
                            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                        ),
                        crate::HashKind::Sha512 => assert_eq!(
                            digest,
                            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
                        ),
                        crate::HashKind::Sha3_256 => assert_eq!(
                            digest,
                            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
                        ),
                    }
                }
            }
            assert_eq!(len, 0);
        }

        #[test]
        fn test_checksumming_writer_with_data() {
            use std::io::Write;

            let mut buf: Vec<u8> = Vec::new();
            let mut writer = crate::ChecksummingWriter::new(
                &mut buf,
                &[
                    crate::HashKind::Sha256,
                    crate::HashKind::Sha512,
                    crate::HashKind::Sha3_256,
                ],
            );
            writer.write_all(b"hello world!").unwrap();
            let (hash_values, len) = writer.into_digests();
            assert_eq!(buf.as_slice(), b"hello world!");
            for kind in [
                crate::HashKind::Sha256,
                crate::HashKind::Sha512,
                crate::HashKind::Sha3_256,
            ] {
                if let Some(digest) = hash_values.get(&kind) {
                    match kind {
                        crate::HashKind::Sha256 => assert_eq!(
                            digest,
                            "7509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9"
                        ),
                        crate::HashKind::Sha512 => assert_eq!(
                            digest,
                            "db9b1cd3262dee37756a09b9064973589847caa8e53d31a9d142ea2701b1b28abd97838bb9a27068ba305dc8d04a45a1fcf079de54d607666996b3cc54f6b67c"
                        ),
                        crate::HashKind::Sha3_256 => assert_eq!(
                            digest,
                            "9c24b06143c07224c897bac972e6e92b46cf18063f1a469ebe2f7a0966306105",
                        ),
                    }
                }
            }
            assert_eq!(len, b"hello world!".len());
        }
    }
}
