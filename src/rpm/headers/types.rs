//! A collection of types used in various header records.
use crate::{constants::*, errors};
use digest::Digest;

/// Offsets into an RPM Package (from the start of the file) demarking locations of each section
///
/// See: `RPMPackage::get_package_component_offsets()`
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RPMPackageSegmentOffsets {
    pub lead: u64,
    pub signature_header: u64,
    pub header: u64,
    pub payload: u64,
}

/// Describes a file present in the rpm file.
pub struct RPMFileEntry {
    pub(crate) size: u64,
    pub(crate) mode: FileMode,
    pub(crate) modified_at: u32,
    pub(crate) sha_checksum: String,
    pub(crate) link: String,
    pub(crate) flags: FileFlags,
    pub(crate) user: String,
    pub(crate) group: String,
    pub(crate) base_name: String,
    #[allow(unused)]
    pub(crate) dir: String,
    pub(crate) content: Vec<u8>,
}

#[non_exhaustive]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum FileMode {
    // It does not really matter if we use u16 or i16 since all we care about
    // is the bit representation which is the same for both.
    Dir { permissions: u16 },
    Regular { permissions: u16 },
    // For "Invalid" we use a larger integer since it is possible to create an invalid
    // FileMode by providing an overflowing integer.
    Invalid { raw_mode: i32, reason: &'static str },
}

// there are more file types but in the context of RPM, only regular and directory should be relevant.
// See <https://man7.org/linux/man-pages/man7/inode.7.html> section "The file type and mode"
const FILE_TYPE_BIT_MASK: u16 = 0o170000; // bit representation = "1111000000000000"
const PERMISSIONS_BIT_MASK: u16 = 0o7777; // bit representation = "0000111111111111"
const REGULAR_FILE_TYPE: u16 = 0o100000; //  bit representation = "1000000000000000"
const DIR_FILE_TYPE: u16 = 0o040000; //      bit representation = "0100000000000000"

// @todo: <https://github.com/rpm-rs/rpm/issues/52>
impl From<u16> for FileMode {
    fn from(raw_mode: u16) -> Self {
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
        match file_type {
            DIR_FILE_TYPE => FileMode::Dir { permissions },
            REGULAR_FILE_TYPE => FileMode::Regular { permissions },
            _ => FileMode::Invalid {
                raw_mode: raw_mode as i32,
                reason: "unknown file type",
            },
        }
    }
}

impl From<i32> for FileMode {
    fn from(raw_mode: i32) -> Self {
        // since we ultimately only deal with 16bit integers
        // we need to check if a safe conversion to 16bit is doable.
        if raw_mode > u16::MAX.into() || raw_mode < i16::MIN.into() {
            FileMode::Invalid {
                raw_mode,
                reason: "provided integer is out of 16bit bounds",
            }
        } else {
            FileMode::from(raw_mode as u16)
        }
    }
}

impl FileMode {
    /// Create a new Regular instance. `permissions` can be between 0 and 0o7777. Values greater will be set to 0o7777.
    pub fn regular(permissions: u16) -> Self {
        FileMode::Regular {
            permissions: permissions & PERMISSIONS_BIT_MASK,
        }
    }

    /// Create a new Dir instance. `permissions` can be between 0 and 0o7777. Values greater will be set to 0o7777.
    pub fn dir(permissions: u16) -> Self {
        FileMode::Dir {
            permissions: permissions & PERMISSIONS_BIT_MASK,
        }
    }

    /// Usually this should be done with TryFrom, but since we already have a `From` implementation,
    /// we run into this issue: <https://github.com/rust-lang/rust/issues/50133>
    pub fn try_from_raw(raw: i32) -> Result<Self, errors::RPMError> {
        let mode: FileMode = raw.into();
        mode.to_result()
    }

    /// Turns this FileMode into a result. If the mode is Invalid, it will be converted into
    /// RPMError::InvalidFileMode. Otherwise it is Ok(self).
    pub fn to_result(self) -> Result<Self, errors::RPMError> {
        match self {
            Self::Invalid { raw_mode, reason } => {
                Err(errors::RPMError::InvalidFileMode { raw_mode, reason })
            }
            _ => Ok(self),
        }
    }

    /// Returns the complete file mode (type and permissions)
    pub fn raw_mode(&self) -> u16 {
        match self {
            Self::Dir { permissions } | Self::Regular { permissions } => {
                *permissions | self.file_type()
            }
            Self::Invalid {
                raw_mode,
                reason: _,
            } => *raw_mode as u16,
        }
    }

    pub fn file_type(&self) -> u16 {
        match self {
            Self::Dir { permissions: _ } => DIR_FILE_TYPE,
            Self::Regular { permissions: _ } => REGULAR_FILE_TYPE,
            Self::Invalid {
                raw_mode,
                reason: _,
            } => *raw_mode as u16 & FILE_TYPE_BIT_MASK,
        }
    }

    pub fn permissions(&self) -> u16 {
        match self {
            Self::Dir { permissions } | Self::Regular { permissions } => *permissions,
            Self::Invalid {
                raw_mode,
                reason: _,
            } => *raw_mode as u16 & PERMISSIONS_BIT_MASK,
        }
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

/// Description of file modes.
///
/// A subset
pub struct RPMFileOptions {
    pub(crate) destination: String,
    pub(crate) user: String,
    pub(crate) group: String,
    pub(crate) symlink: String,
    pub(crate) mode: FileMode,
    pub(crate) flag: FileFlags,
    pub(crate) inherit_permissions: bool,
}

impl RPMFileOptions {
    #[allow(clippy::new_ret_no_self)]
    pub fn new<T: Into<String>>(dest: T) -> RPMFileOptionsBuilder {
        RPMFileOptionsBuilder {
            inner: RPMFileOptions {
                destination: dest.into(),
                user: "root".to_string(),
                group: "root".to_string(),
                symlink: "".to_string(),
                mode: FileMode::regular(0o664),
                flag: FileFlags::empty(),
                inherit_permissions: true,
            },
        }
    }
}

pub struct RPMFileOptionsBuilder {
    inner: RPMFileOptions,
}

impl RPMFileOptionsBuilder {
    pub fn user<T: Into<String>>(mut self, user: T) -> Self {
        self.inner.user = user.into();
        self
    }

    pub fn group<T: Into<String>>(mut self, group: T) -> Self {
        self.inner.group = group.into();
        self
    }

    pub fn symlink<T: Into<String>>(mut self, symlink: T) -> Self {
        self.inner.symlink = symlink.into();
        self
    }

    pub fn mode<T: Into<FileMode>>(mut self, mode: T) -> Self {
        self.inner.mode = mode.into();
        self.inner.inherit_permissions = false;
        self
    }

    pub fn is_doc(mut self) -> Self {
        self.inner.flag = FileFlags::DOC;
        self
    }

    pub fn is_config(mut self) -> Self {
        self.inner.flag = FileFlags::CONFIG;
        self
    }

    pub fn is_ghost(mut self) -> Self {
        self.inner.flag = FileFlags::GHOST;
        self
    }

    pub fn is_license(mut self) -> Self {
        self.inner.flag = FileFlags::LICENSE;
        self
    }

    pub fn is_readme(mut self) -> Self {
        self.inner.flag = FileFlags::README;
        self
    }
}

impl From<RPMFileOptionsBuilder> for RPMFileOptions {
    fn from(builder: RPMFileOptionsBuilder) -> Self {
        builder.inner
    }
}

/// Description of a dependency as present in a RPM header record.
#[derive(Debug, PartialEq, Eq)]
pub struct Dependency {
    pub(crate) dep_name: String,
    pub(crate) flags: DependencyFlags,
    pub(crate) version: String,
}

impl Dependency {
    pub fn less<E, T>(dep_name: T, version: E) -> Self
    where
        T: Into<String>,
        E: Into<String>,
    {
        Self::new(dep_name.into(), DependencyFlags::LESS, version.into())
    }

    pub fn less_eq<E, T>(dep_name: T, version: E) -> Self
    where
        T: Into<String>,
        E: Into<String>,
    {
        Self::new(
            dep_name.into(),
            DependencyFlags::LESS | DependencyFlags::EQUAL,
            version.into(),
        )
    }

    pub fn eq<E, T>(dep_name: T, version: E) -> Self
    where
        T: Into<String>,
        E: Into<String>,
    {
        Self::new(dep_name.into(), DependencyFlags::EQUAL, version.into())
    }

    pub fn greater<E, T>(dep_name: T, version: E) -> Self
    where
        T: Into<String>,
        E: Into<String>,
    {
        Self::new(dep_name.into(), DependencyFlags::GREATER, version.into())
    }

    pub fn greater_eq<E, T>(dep_name: T, version: E) -> Self
    where
        T: Into<String>,
        E: Into<String>,
    {
        Self::new(
            dep_name.into(),
            DependencyFlags::GREATER | DependencyFlags::EQUAL,
            version.into(),
        )
    }

    pub fn any<T>(dep_name: T) -> Self
    where
        T: Into<String>,
    {
        Self::new(dep_name.into(), DependencyFlags::ANY, "".to_string())
    }

    pub fn rpmlib<E, T>(dep_name: T, version: E) -> Self
    where
        T: Into<String>,
        E: Into<String>,
    {
        Self::new(
            dep_name.into(),
            DependencyFlags::RPMLIB | DependencyFlags::EQUAL,
            version.into(),
        )
    }

    fn new(dep_name: String, flags: DependencyFlags, version: String) -> Self {
        Dependency {
            dep_name,
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
        }

        let test_table = vec![
            (0o10_0664, Ok(FileMode::regular(0o664))),
            (0o04_0665, Ok(FileMode::dir(0o665))),
            // test sticky bit
            (0o10_1664, Ok(FileMode::regular(0o1664))),
            (
                0o664,
                Err(errors::RPMError::InvalidFileMode {
                    raw_mode: 0o664,
                    reason: "unknown file type",
                }),
            ),
            (
                0o27_1664,
                Err(errors::RPMError::InvalidFileMode {
                    raw_mode: 0o27_1664,
                    reason: "provided integer is out of 16bit bounds",
                }),
            ),
        ];

        // test try_from_raw
        for (testant, expected) in test_table {
            let result = FileMode::try_from_raw(testant);
            match (&expected, &result) {
                (Ok(expected), Ok(actual)) => {
                    assert_eq!(expected, actual);
                }
                (Err(expected), Err(actual)) => {
                    if let errors::RPMError::InvalidFileMode {
                        raw_mode: actual_raw_mode,
                        reason: actual_reason,
                    } = actual
                    {
                        if let errors::RPMError::InvalidFileMode {
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

        // test into methods
        let test_table = vec![
            (0o10_0755, FileMode::regular(0o0755), REGULAR_FILE_TYPE),
            (0o10_1755, FileMode::regular(0o1755), REGULAR_FILE_TYPE),
            (0o04_0755, FileMode::dir(0o0755), DIR_FILE_TYPE),
            (
                0o20_0755,
                FileMode::Invalid {
                    raw_mode: 0o20_0755,
                    reason: "provided integer is out of 16bit bounds",
                },
                0,
            ),
            (
                0o0755,
                FileMode::Invalid {
                    raw_mode: 0o0755,
                    reason: "unknown file type",
                },
                0,
            ),
        ];
        for (raw_mode, expected_mode, expected_type) in test_table {
            let mode = FileMode::from(raw_mode);
            assert_eq!(expected_mode, mode);
            assert_eq!(raw_mode as u16, mode.raw_mode());
            assert_eq!(expected_type, mode.file_type());
        }
        Ok(())
    }
}
