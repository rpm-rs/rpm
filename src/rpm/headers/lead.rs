use binrw::io::NoSeek;
use binrw::{BinRead, BinReaderExt, BinWrite, BinWriterExt};
use std::io::Cursor;

use crate::constants::*;
use crate::errors::*;

/// Lead of an rpm header.
///
/// Used to contain valid data, now only a very limited subset is used
/// and the remaining data is set to fixed values such that compatibility is kept.
/// Only the "magic number" is still relevant as it is used to detect rpm files.
#[derive(BinRead, BinWrite, Eq, PartialEq, Debug)]
pub struct Lead {
    magic: [u8; 4],
    major: u8,
    minor: u8,
    package_type: u16,
    arch: u16,
    #[br(map = |v: [u8; 66]| String::from_utf8_lossy(&v).to_string())]
    #[bw(map = |name: &String| {
        let mut name_arr = [0u8; 66];
        let name_size = std::cmp::min(name_arr.len() - 1, name.len());
        name_arr[..name_size].clone_from_slice(&name.as_bytes()[..name_size]);
        name_arr
    })]
    name: String,
    os: u16,
    signature_type: u16,
    reserved: [u8; 16],
}

impl Lead {
    pub(crate) fn parse(input: &[u8]) -> Result<Self, Error> {
        let mut reader = Cursor::new(input);
        // TODO: map error
        Ok(reader.read_be().unwrap())
    }

    pub(crate) fn write(&self, out: &mut impl std::io::Write) -> Result<(), Error> {
        // TODO: map error
        NoSeek::new(out).write_be(self).unwrap();
        Ok(())
    }

    pub(crate) fn new(name: &str) -> Self {
        Self {
            magic: RPM_MAGIC,
            major: 3,
            minor: 0,
            package_type: 0,
            arch: 0,
            name: name.to_string(),
            os: 1,
            signature_type: 5,
            reserved: [0; 16],
        }
    }
}
