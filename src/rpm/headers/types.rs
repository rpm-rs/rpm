//! A collection of types used in various header records.
use std::str::FromStr;

use crate::{constants::*, errors, Timestamp};
use capctl::FileCaps;
use digest::Digest;

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

/// Describes a file present in the rpm file.
pub struct PackageFileEntry {
    pub size: u64,
    pub mode: FileMode, // todo: maybe we can compute these lazily for more permissive error handling?
    pub modified_at: Timestamp,
    pub sha_checksum: String,
    pub link: String,
    pub flags: FileFlags,
    pub user: String,
    pub group: String,
    pub base_name: String,
    pub dir: String,
    pub caps: Option<FileCaps>,
    pub(crate) content: Vec<u8>,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum FileType {
    Dir,
    Regular,
    SymbolicLink,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub struct FileMode {
    file_type: FileType,
    permissions: u16,
}

// there are more file types but in the context of RPM, only regular and directory and symbolic file should be relevant.
// See <https://man7.org/linux/man-pages/man7/inode.7.html> section "The file type and mode"
const FILE_TYPE_BIT_MASK: u16 = 0o170000; // bit representation = "1111000000000000"
const PERMISSIONS_BIT_MASK: u16 = 0o7777; // bit representation = "0000111111111111"

const REGULAR_FILE_TYPE: u16 = 0o100000; //  bit representation = "1000000000000000"
const DIR_FILE_TYPE: u16 = 0o040000; //      bit representation = "0100000000000000"
const SYMBOLIC_LINK_FILE_TYPE: u16 = 0o120000; // bit representation = "1010000000000000"

impl TryFrom<u16> for FileMode {
    type Error = errors::Error;

    fn try_from(raw_mode: u16) -> Result<Self, Self::Error> {
        // example
        //  1111000000000000  (0o170000)  <- file type bit mask
        // &1000000111101101  (0o100755)  <- regular executable file
        // -----------------------------
        //  1000000000000000  (0o100000)  <- type for regular files
        //
        // we effectively extract the file type bits with an AND operation.
        // Here are two links for a quick refresh:
        // <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Bitwise_AND>
        // <https://en.wikipedia.org/wiki/Bitwise_operation#AND>
        let file_type = raw_mode & FILE_TYPE_BIT_MASK;
        let permissions = raw_mode & PERMISSIONS_BIT_MASK;
        let file_type = match file_type {
            DIR_FILE_TYPE => Ok(FileType::Dir),
            REGULAR_FILE_TYPE => Ok(FileType::Regular),
            SYMBOLIC_LINK_FILE_TYPE => Ok(FileType::SymbolicLink),
            _ => Err(Self::Error::InvalidFileMode {
                raw_mode: raw_mode as i32,
                reason: "unknown file type",
            }),
        }?;

        Ok(FileMode {
            file_type,
            permissions,
        })
    }
}

impl TryFrom<i32> for FileMode {
    type Error = errors::Error;

    fn try_from(raw_mode: i32) -> Result<Self, Self::Error> {
        // since we ultimately only deal with 16bit integers
        // we need to check if a safe conversion to 16bit is doable.
        if raw_mode > u16::MAX.into() || raw_mode < i16::MIN.into() {
            Err(Self::Error::InvalidFileMode {
                raw_mode,
                reason: "provided integer is out of 16bit bounds",
            })
        } else {
            Ok(FileMode::try_from(raw_mode as u16)?)
        }
    }
}

// @todo: 0o7777? should it be 0o777?
impl FileMode {
    /// Create a new Regular instance. `permissions` can be between 0 and 0o7777. Values greater will be set to 0o7777.
    pub fn regular(permissions: u16) -> Self {
        FileMode {
            file_type: FileType::Regular,
            permissions: permissions & PERMISSIONS_BIT_MASK,
        }
    }

    /// Create a new Dir instance. `permissions` can be between 0 and 0o7777. Values greater will be set to 0o7777.
    pub fn dir(permissions: u16) -> Self {
        FileMode {
            file_type: FileType::Dir,
            permissions: permissions & PERMISSIONS_BIT_MASK,
        }
    }

    /// Create a new Symbolic link instance. `permissions` can be between 0 and 0o7777. Values greater will be set to 0o7777.
    pub fn symbolic_link(permissions: u16) -> Self {
        FileMode {
            file_type: FileType::SymbolicLink,
            permissions: permissions & PERMISSIONS_BIT_MASK,
        }
    }

    /// Returns the complete file mode (type and permissions)
    pub fn raw_mode(&self) -> u16 {
        self.file_type() | self.permissions
    }

    pub fn file_type(&self) -> u16 {
        match self.file_type {
            FileType::Dir => DIR_FILE_TYPE,
            FileType::Regular => REGULAR_FILE_TYPE,
            FileType::SymbolicLink => SYMBOLIC_LINK_FILE_TYPE,
        }
    }

    pub fn permissions(&self) -> u16 {
        self.permissions
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

/// A collection of options used when constructing a new file entry.
#[derive(Debug)]
pub struct FileOptions {
    pub(crate) destination: String,
    pub(crate) user: String,
    pub(crate) group: String,
    pub(crate) symlink: String,
    pub(crate) mode: FileMode,
    pub(crate) flag: FileFlags,
    pub(crate) inherit_permissions: bool,
    pub(crate) caps: Option<FileCaps>,
}

// @todo: should we even have "default permissions" / mode, or use Option<FileMode>?
// if they can be skipped (unsure), 'inherit_permissions' could go away
impl FileOptions {
    /// Create a new FileOptions for a regular file
    #[allow(clippy::new_ret_no_self)]
    pub fn regular(dest: impl Into<String>) -> FileOptionsBuilder {
        FileOptionsBuilder {
            inner: FileOptions {
                destination: dest.into(),
                user: "root".to_string(),
                group: "root".to_string(),
                symlink: "".to_string(),
                mode: FileMode::regular(0o664),
                flag: FileFlags::empty(),
                inherit_permissions: true,
                caps: None,
            },
        }
    }

    /// Create a new FileOptions for a directory
    ///
    /// Used to explicitly own the directory itself but not it's contents. This does NOT
    /// process any of the contents of a directory.
    #[allow(clippy::new_ret_no_self)]
    pub fn dir(dest: impl Into<String>) -> FileOptionsBuilder {
        // @todo: is this problematic? `with_file` has a source argument, but I do not believe %dir uses
        // any "source" necessarily, just a destination.  Maybe we need `PackageBuilder::with_dir()`,
        // except that sounds like it would process files recursively inside a directory, and we would
        // still need to duplicate much of this code.

        FileOptionsBuilder {
            inner: FileOptions {
                destination: dest.into(),
                user: "root".to_string(),
                group: "root".to_string(),
                symlink: "".to_string(),
                mode: FileMode::regular(0o664),
                flag: FileFlags::empty(),
                inherit_permissions: true,
                caps: None,
            },
        }
    }

    /// Create a new FileOptions for a symbolic link
    #[allow(clippy::new_ret_no_self)]
    pub fn symbolic_link(dest: impl Into<String>, link: impl Into<String>) -> FileOptionsBuilder {
        FileOptionsBuilder {
            inner: FileOptions {
                destination: dest.into(),
                user: "root".to_string(),
                group: "root".to_string(),
                symlink: link.into(),
                mode: FileMode::symbolic_link(0o664),
                flag: FileFlags::empty(),
                inherit_permissions: true,
                caps: None,
            },
        }
    }
}

#[derive(Debug)]
pub struct FileOptionsBuilder {
    inner: FileOptions,
}

// @todo: finish support for different types of file attributes (rpmfileAttrs)
// see: constants::FileFlags
// @todo: should we represent "defattr", that is, set default permissions on all files in a package
// without needing to explicitly them for each FileOptions
// @todo: how about "%docdir"?  which automatically marks subsequent files in those directories as docs
impl FileOptionsBuilder {
    /// Set the user for the file to be installed by the package
    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.inner.user = user.into();
        self
    }

    /// Set the group for the file to be installed by the package
    pub fn group(mut self, group: impl Into<String>) -> Self {
        self.inner.group = group.into();
        self
    }

    /// Set the permissions for the file to be installed by the package
    pub fn permissions(mut self, perms: u16) -> Self {
        self.inner.mode.permissions = perms;
        self.inner.inherit_permissions = false;
        self
    }

    // @todo: should doc, license, ghost be moved to `FileOptions::doc()`, etc?

    /// Set POSIX.1e draft 15 file capabilities for the file to be installed by the package
    ///
    /// see: <https://man7.org/linux/man-pages/man7/capabilities.7.html>
    pub fn caps(mut self, caps: impl Into<String>) -> Result<Self, errors::Error> {
        // verify capabilities
        self.inner.caps = match FileCaps::from_str(&caps.into()) {
            Ok(caps) => Some(caps),
            Err(e) => {
                return Err(errors::Error::InvalidCapabilities {
                    caps: e.to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Indicates that this file is documentation.
    ///
    /// Documentation files are tracked in the rpm database for easier lookup.
    pub fn is_doc(mut self) -> Self {
        self.inner.flag = FileFlags::DOC;
        self
    }

    /// Indicates that this file is a software license file.
    pub fn is_license(mut self) -> Self {
        self.inner.flag = FileFlags::LICENSE;
        self
    }

    /// Indicates that this file is a config file.
    ///
    /// Config files are handled differently during upgrades - newly provided config files are
    /// given the extension '.rpmnew' to avoid overwriting any changes that have been made to
    /// the existing config.
    pub fn is_config(mut self) -> Self {
        self.inner.flag = FileFlags::CONFIG;
        self
    }

    /// Indicates that this file shouldn't be included in the package. It is used for e.g. log files,
    /// where the contents of the file aren't important to the package, but declaring the ownership
    /// and attributes of the file is.
    pub fn is_ghost(mut self) -> Self {
        self.inner.flag = FileFlags::GHOST;
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
    pub fn less(dep_name: impl Into<String>, version: impl Into<String>) -> Self {
        Self::new(dep_name.into(), DependencyFlags::LESS, version.into())
    }

    pub fn less_eq(dep_name: impl Into<String>, version: impl Into<String>) -> Self {
        Self::new(
            dep_name.into(),
            DependencyFlags::LESS | DependencyFlags::EQUAL,
            version.into(),
        )
    }

    pub fn eq(dep_name: impl Into<String>, version: impl Into<String>) -> Self {
        Self::new(dep_name.into(), DependencyFlags::EQUAL, version.into())
    }

    pub fn greater(dep_name: impl Into<String>, version: impl Into<String>) -> Self {
        Self::new(dep_name.into(), DependencyFlags::GREATER, version.into())
    }

    pub fn greater_eq(dep_name: impl Into<String>, version: impl Into<String>) -> Self {
        Self::new(
            dep_name.into(),
            DependencyFlags::GREATER | DependencyFlags::EQUAL,
            version.into(),
        )
    }

    pub fn any(dep_name: impl Into<String>) -> Self {
        Self::new(dep_name.into(), DependencyFlags::ANY, "".to_string())
    }

    pub fn rpmlib(dep_name: impl Into<String>, version: impl Into<String>) -> Self {
        Self::new(
            dep_name.into(),
            DependencyFlags::RPMLIB | DependencyFlags::EQUAL,
            version.into(),
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

/// A wrapper for calculating the sha256 checksum of the contents written to it
pub struct Sha256Writer<W> {
    writer: W,
    hasher: sha2::Sha256,
}

impl<W> Sha256Writer<W> {
    pub fn new(writer: W) -> Self {
        Sha256Writer {
            writer,
            hasher: sha2::Sha256::new(),
        }
    }

    pub fn into_digest(self) -> impl AsRef<[u8]> {
        self.hasher.finalize()
    }
}

impl<W: std::io::Write> std::io::Write for Sha256Writer<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.hasher.update(buf);
        self.writer.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
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

        let test_table = vec![
            (0o10_0664, Ok(FileMode::regular(0o664))),
            (0o04_0665, Ok(FileMode::dir(0o665))),
            // test sticky bit
            (0o10_1664, Ok(FileMode::regular(0o1664))),
            (0o12_0664, Ok(FileMode::symbolic_link(0o0664))),
            (0o12_1664, Ok(FileMode::symbolic_link(0o1664))),
            (
                0o664,
                Err(errors::Error::InvalidFileMode {
                    raw_mode: 0o664,
                    reason: "unknown file type",
                }),
            ),
            (
                0o27_1664,
                Err(errors::Error::InvalidFileMode {
                    raw_mode: 0o27_1664,
                    reason: "provided integer is out of 16bit bounds",
                }),
            ),
        ];

        // test try_from_raw
        for (testant, expected) in test_table {
            let result = FileMode::try_from(testant);
            match (&expected, &result) {
                (Ok(expected), Ok(actual)) => {
                    assert_eq!(expected, actual);
                }
                (Err(expected), Err(actual)) => {
                    if let errors::Error::InvalidFileMode {
                        raw_mode: actual_raw_mode,
                        reason: actual_reason,
                    } = actual
                    {
                        if let errors::Error::InvalidFileMode {
                            raw_mode: expected_raw_mode,
                            reason: expected_reason,
                        } = expected
                        {
                            assert_eq!(expected_raw_mode, actual_raw_mode);
                            assert_eq!(expected_reason, actual_reason);
                        } else {
                            unreachable!();
                        }
                    } else {
                        panic!("invalid error type");
                    }
                }
                _ => panic!("a and b not equal,{:?} vs {:?}", expected, result),
            }
        }

        // // test into methods
        // let test_table = vec![
        //     (0o10_0755, Ok(FileMode::regular(0o0755)), REGULAR_FILE_TYPE),
        //     (0o10_1755, Ok(FileMode::regular(0o1755)), REGULAR_FILE_TYPE),
        //     (0o04_0755, Ok(FileMode::dir(0o0755)), DIR_FILE_TYPE),
        //     (
        //         0o12_0755,
        //         Ok(FileMode::symbolic_link(0o0755)),
        //         SYMBOLIC_LINK_FILE_TYPE,
        //     ),
        //     (
        //         0o12_1755,
        //         Ok(FileMode::symbolic_link(0o1755)),
        //         SYMBOLIC_LINK_FILE_TYPE,
        //     ),
        //     (
        //         0o20_0755,
        //         Err(FileMode::Invalid {
        //             raw_mode: 0o20_0755,
        //             reason: "provided integer is out of 16bit bounds",
        //         }),
        //         0,
        //     ),
        //     (
        //         0o0755,
        //         Err(FileMode::Invalid {
        //             raw_mode: 0o0755,
        //             reason: "unknown file type",
        //         }),
        //         0,
        //     ),
        // ];
        // for (raw_mode, expected_mode, expected_type) in test_table {
        //     let mode = FileMode::try_from(raw_mode);
        //     assert_eq!(expected_mode, mode);
        //     assert_eq!(raw_mode as u16, mode.raw_mode());
        //     assert_eq!(expected_type, mode.file_type());
        // }
        Ok(())
    }

    #[test]
    fn test_verify_capabilities_valid() {
        let blank_file = crate::FileOptions::regular("/usr/bin/awesome");
        blank_file.caps("cap_net_admin,cap_net_raw+p").unwrap();
    }

    #[test]
    fn test_verify_capabilities_invalid() -> Result<(), crate::errors::Error> {
        let blank_file = crate::FileOptions::regular("/usr/bin/awesome");
        blank_file.caps("cap_net_an,cap_net_raw+p").unwrap_err();
        Ok(())
    }
}
