use nom::bytes::complete;
use nom::number::complete::{be_u16, be_u8};
use std::convert::TryInto;

use crate::constants::*;
use crate::errors::*;

#[cfg(feature = "async-tokio")]
use tokio::io::AsyncWriteExt;

/// Lead of an rpm header.
///
/// Used to contain valid data,
/// now only a very limited subset is used
/// and the remaining data is set to fixed values
/// such that compatibility is kept.
/// This is also used by magic and other libraries
/// to detect rpm files.
pub struct Lead {
    magic: [u8; 4],
    major: u8,
    minor: u8,
    package_type: u16,
    arch: u16,
    name: [u8; 66],
    os: u16,
    signature_type: u16,
    reserved: [u8; 16],
}

impl std::fmt::Debug for Lead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = String::from_utf8_lossy(&self.name);
        f.debug_struct("Lead")
            .field("magic", &self.magic)
            .field("major", &self.major)
            .field("minor", &self.minor)
            .field("package_type", &self.package_type)
            .field("arch", &self.arch)
            .field("name", &name)
            .field("os", &self.os)
            .field("signature_type", &self.signature_type)
            .field("reserved", &self.reserved)
            .finish()
    }
}

impl Lead {
    pub(crate) fn parse(input: &[u8]) -> Result<Self, RPMError> {
        let (rest, magic) = complete::take(4usize)(input)?;
        for i in 0..magic.len() {
            if magic[i] != RPM_MAGIC[i] {
                return Err(RPMError::InvalidMagic {
                    expected: RPM_MAGIC[i],
                    actual: magic[i],
                    complete_input: input.to_vec(),
                });
            }
        }
        let (rest, major) = be_u8(rest)?;
        if major != 3 {
            return Err(RPMError::InvalidLeadMajorVersion(major));
        }
        let (rest, minor) = be_u8(rest)?;
        if minor != 0 {
            return Err(RPMError::InvalidLeadMinorVersion(minor));
        }
        let (rest, pkg_type) = be_u16(rest)?;

        if pkg_type > 1 {
            return Err(RPMError::InvalidLeadPKGType(pkg_type));
        }

        let (rest, arch) = be_u16(rest)?;
        let (rest, name) = complete::take(66usize)(rest)?;

        let (rest, os) = be_u16(rest)?;
        if os != 1 {
            return Err(RPMError::InvalidLeadOSType(os));
        }

        let (rest, sigtype) = be_u16(rest)?;
        if sigtype != 5 {
            return Err(RPMError::InvalidLeadSignatureType(sigtype));
        }

        if rest.len() != 16 {
            return Err(RPMError::InvalidReservedSpaceSize {
                expected: 16,
                actual: rest.len(),
            });
        }

        let mut name_arr: [u8; 66] = [0; 66];
        name_arr.copy_from_slice(name);

        //save unwrap here since we've checked length of slices.
        Ok(Lead {
            magic: magic.try_into().unwrap(),
            major,
            minor,
            package_type: pkg_type,
            arch,
            name: name_arr,
            os,
            signature_type: sigtype,
            reserved: rest.try_into().unwrap(),
        })
    }
    #[cfg(feature = "async-tokio")]
    pub(crate) async fn write_async<W: tokio::io::AsyncWrite + Unpin>(
        &self,
        out: &mut W,
    ) -> Result<(), RPMError> {
        out.write_all(&self.magic).await?;
        out.write_all(&self.major.to_be_bytes()).await?;
        out.write_all(&self.minor.to_be_bytes()).await?;
        out.write_all(&self.package_type.to_be_bytes()).await?;
        out.write_all(&self.arch.to_be_bytes()).await?;
        out.write_all(&self.name).await?;
        out.write_all(&self.os.to_be_bytes()).await?;
        out.write_all(&self.signature_type.to_be_bytes()).await?;
        out.write_all(&self.reserved).await?;
        Ok(())
    }

    pub(crate) fn write<W: std::io::Write>(&self, out: &mut W) -> Result<(), RPMError> {
        out.write_all(&self.magic)?;
        out.write_all(&self.major.to_be_bytes())?;
        out.write_all(&self.minor.to_be_bytes())?;
        out.write_all(&self.package_type.to_be_bytes())?;
        out.write_all(&self.arch.to_be_bytes())?;
        out.write_all(&self.name)?;
        out.write_all(&self.os.to_be_bytes())?;
        out.write_all(&self.signature_type.to_be_bytes())?;
        out.write_all(&self.reserved)?;
        Ok(())
    }

    pub(crate) fn new(name: &str) -> Self {
        let mut name_arr = [0; 66];
        // the last byte needs to be the null terminator
        let name_size = std::cmp::min(name_arr.len() - 1, name.len());

        name_arr[..name_size].clone_from_slice(&name.as_bytes()[..name_size]);
        Lead {
            magic: RPM_MAGIC,
            major: 3,
            minor: 0,
            package_type: 0,
            arch: 0,
            name: name_arr,
            os: 1,
            signature_type: 5,
            reserved: [0; 16],
        }
    }
}

impl PartialEq for Lead {
    fn eq(&self, other: &Lead) -> bool {
        for i in 0..self.name.len() {
            if other.name[i] != self.name[i] {
                return false;
            }
        }
        self.magic == other.magic
            && self.major == other.major
            && self.minor == other.minor
            && self.package_type == other.package_type
            && self.arch == other.arch
            && self.os == other.os
            && self.signature_type == other.signature_type
            && self.reserved == other.reserved
    }
}
