//! A collection of types used in various header records.

use crate::constants::*;

/// Describes a file present in the rpm file.
pub struct RPMFileEntry {
    pub(crate) size: i32,
    pub(crate) mode: i16,
    pub(crate) modified_at: i32,
    pub(crate) sha_checksum: String,
    pub(crate) link: String,
    pub(crate) flag: i32,
    pub(crate) user: String,
    pub(crate) group: String,
    pub(crate) base_name: String,
    pub(crate) dir: String,
    pub(crate) content: Option<Vec<u8>>,
}

/// Description of file modes.
///
/// A subset
pub struct RPMFileOptions {
    pub(crate) destination: String,
    pub(crate) user: String,
    pub(crate) group: String,
    pub(crate) symlink: String,
    pub(crate) mode: i32,
    pub(crate) flag: i32,
    pub(crate) inherit_permissions: bool,
}

impl RPMFileOptions {
    pub fn new<T: Into<String>>(dest: T) -> RPMFileOptionsBuilder {
        RPMFileOptionsBuilder {
            inner: RPMFileOptions {
                destination: dest.into(),
                user: "root".to_string(),
                group: "root".to_string(),
                symlink: "".to_string(),
                mode: 0o100_664,
                flag: 0,
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

    pub fn mode(mut self, mode: i32) -> Self {
        self.inner.mode = mode;
        self.inner.inherit_permissions = false;
        self
    }

    pub fn is_doc(mut self) -> Self {
        self.inner.flag = RPMFILE_DOC;
        self
    }

    pub fn is_config(mut self) -> Self {
        self.inner.flag = RPMFILE_CONFIG;
        self
    }
}

impl Into<RPMFileOptions> for RPMFileOptionsBuilder {
    fn into(self) -> RPMFileOptions {
        self.inner
    }
}

/// Description of a dependency as present in a RPM header record.
pub struct Dependency {
    pub(crate) dep_name: String,
    pub(crate) sense: u32,
    pub(crate) version: String,
}

impl Dependency {
    pub fn less<E, T>(dep_name: T, version: E) -> Self
    where
        T: Into<String>,
        E: Into<String>,
    {
        Self::new(dep_name.into(), RPMSENSE_LESS, version.into())
    }

    pub fn less_eq<E, T>(dep_name: T, version: E) -> Self
    where
        T: Into<String>,
        E: Into<String>,
    {
        Self::new(
            dep_name.into(),
            RPMSENSE_LESS | RPMSENSE_EQUAL,
            version.into(),
        )
    }

    pub fn eq<E, T>(dep_name: T, version: E) -> Self
    where
        T: Into<String>,
        E: Into<String>,
    {
        Self::new(dep_name.into(), RPMSENSE_EQUAL, version.into())
    }

    pub fn greater<E, T>(dep_name: T, version: E) -> Self
    where
        T: Into<String>,
        E: Into<String>,
    {
        Self::new(dep_name.into(), RPMSENSE_GREATER, version.into())
    }

    pub fn greater_eq<E, T>(dep_name: T, version: E) -> Self
    where
        T: Into<String>,
        E: Into<String>,
    {
        Self::new(
            dep_name.into(),
            RPMSENSE_GREATER | RPMSENSE_EQUAL,
            version.into(),
        )
    }

    pub fn any<T>(dep_name: T) -> Self
    where
        T: Into<String>,
    {
        Self::new(dep_name.into(), RPMSENSE_ANY, "".to_string())
    }

    fn new(dep_name: String, sense: u32, version: String) -> Self {
        Dependency {
            dep_name,
            sense,
            version,
        }
    }
}
