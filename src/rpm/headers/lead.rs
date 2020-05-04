use nom::bytes::complete;
use nom::number::complete::{be_u16, be_u8};
use std::convert::TryInto;

use crate::constants::*;
use crate::errors::*;

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

impl Lead {
    pub(crate) fn parse(input: &[u8]) -> Result<Self, RPMError> {
        let (rest, magic) = complete::take(4usize)(input)?;
        for i in 0..magic.len() {
            if magic[i] != RPM_MAGIC[i] {
                return Err(RPMError::new(&format!(
                    "invalid rpm magic - expected {} but got {}. The whole input was {:x?}",
                    RPM_MAGIC[i], magic[i], input,
                )));
            }
        }
        let (rest, major) = be_u8(rest)?;
        if major != 3 {
            return Err(RPMError::new(&format!(
                "invalid major version - expected 3 but got {}. The whole input was {:x?}",
                major, input
            )));
        }
        let (rest, minor) = be_u8(rest)?;
        if minor != 0 {
            return Err(RPMError::new(&format!(
                "invalid minor version - expected 0 but got {}. The whole input was {:x?}",
                major, input
            )));
        }
        let (rest, pkg_type) = be_u16(rest)?;

        if pkg_type > 1 {
            return Err(RPMError::new(&format!(
                "invalid type - expected 0 or 1 but got {}. The whole input was {:x?}",
                pkg_type, input
            )));
        }

        let (rest, arch) = be_u16(rest)?;
        let (rest, name) = complete::take(66usize)(rest)?;

        let (rest, os) = be_u16(rest)?;
        if os != 1 {
            return Err(RPMError::new(&format!(
                "invalid os-type - expected 1 but got {}. The whole input was {:x?}",
                os, input
            )));
        }

        let (rest, sigtype) = be_u16(rest)?;
        if sigtype != 5 {
            return Err(RPMError::new(&format!(
                "invalid signature-type - expected 5 but got {}. The whole input was {:x?}",
                os, input
            )));
        }

        if rest.len() != 16 {
            return Err(RPMError::new(&format!(
                "invalid size of reserved area - expected length of 16 but got {}. The whole input was {:x?}",
                rest.len(), input
            )));
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
