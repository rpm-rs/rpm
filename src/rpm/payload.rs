//! Read/write `newc` (SVR4) format archives.

// The code in this file is partially copied from the `cpio` crate by Jonathan Creekmore
// (https://github.com/jcreekmore/cpio-rs) under the MIT license.
//
//     MIT License
//
//     Copyright (c) 2016 Jonathan Creekmore
//
//     Permission is hereby granted, free of charge, to any person obtaining a copy of this software
//     and associated documentation files (the "Software"),  to deal in the Software without restriction,
//     including without limitation the rights to use, copy, modify, merge, publish, distribute,
//     sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
//     furnished to do so, subject to the following conditions:
//
//     The above copyright notice and this permission notice shall be included in all copies or
//     substantial portions of the Software.
//
//     THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
//     BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND
//     NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
//     DAMAGES OR OTHER  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//     FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS  IN THE SOFTWARE.
//
// It has been modified to match modifications which are used by the upstream RPM library.
// These modifications are described upstream as follows:
//
//     As cpio is limited to 4 GB (32 bit unsigned) file sizes, RPM since version 4.12
//     uses a stripped down version of cpio for packages with files > 4 GB. This format
//     uses 07070X as magic bytes and the file header otherwise only contains the index
//     number of the file in the RPM header as 8 byte hex string. The file metadata that
//     is normally found in a cpio file header - including the file name - is completely
//     omitted as it is stored in the RPM header already.
//
// Other modifications made to this library include:
//   * Several type renamings
//   * Reader::entry() removed, tests use a helper function
//   * Reader::new() now takes a slice of FileEntry, so that knows how large the files are for the purpose of reading them
//   * Seekable implementation and accompanying tests were deleted - we don't need it

#![allow(dead_code)]

use super::FileEntry;
use std::io::{self, Read, Write};
const HEADER_LEN: usize = 110; // 6 byte magic + 104 bytes for metadata

const STRIPPED_CPIO_HEADER_LEN: usize = 14; // 8 bytes metadata + 6 bytes magic

const MAGIC_NUMBER_NEWASCII: &[u8] = b"070701";
const MAGIC_NUMBER_NEWCRC: &[u8] = b"070702";

const STRIPPED_CPIO_MAGIC_NUMBER: &[u8] = b"07070X"; // Magic number changed to conform with RPM

const TRAILER_NAME: &str = "TRAILER!!!";

/// Whether this header is of the "new ascii" form (without checksum) or the "crc" form which
/// is structurally identical but includes a checksum, depending on the magic number present.
#[derive(Debug, PartialEq)]
enum CpioEntryType {
    Crc,
    Newc,
}

/// Whether the header entry is of a standard CPIO form or the RPM-specific archive form
#[derive(Debug, PartialEq)]
pub enum RpmPayloadEntry {
    Cpio(CpioEntry), // name, file_size
    Stripped(u32),   // file_index
}

/// Metadata about one entry from an archive.
#[derive(Debug, PartialEq)]
pub struct CpioEntry {
    entry_type: CpioEntryType,
    name: String,
    ino: u32,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u32,
    mtime: u32,
    file_size: u32,
    dev_major: u32,
    dev_minor: u32,
    rdev_major: u32,
    rdev_minor: u32,
    checksum: u32,
}

/// Reads one entry header/data from an archive.
pub struct Reader<R: Read> {
    inner: R,
    entry: RpmPayloadEntry,
    file_size: u64,
    bytes_read: u32,
}

/// Builds metadata for one entry to be written into an archive.
#[derive(Clone)]
pub struct Builder {
    name: String,
    ino: u32,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u32,
    mtime: u32,
    dev_major: u32,
    dev_minor: u32,
    rdev_major: u32,
    rdev_minor: u32,
}

/// Writes one entry header/data into an archive.
pub struct Writer<W: Write> {
    inner: W,
    written: u32,
    file_size: u32,
    header_size: usize,
    header: Vec<u8>,
}

fn pad(len: usize) -> Option<Vec<u8>> {
    // pad out to a multiple of 4 bytes
    let overhang = len % 4;
    if overhang != 0 {
        let repeat = 4 - overhang;
        Some(vec![0u8; repeat])
    } else {
        None
    }
}

pub enum ModeFileType {
    Symlink,
    Fifo,
    Char,
    Block,
    NetworkSpecial,
    Socket,
    Directory,
    Regular,
}

impl ModeFileType {
    const MASK: u32 = 0o170000;
}

impl From<ModeFileType> for u32 {
    fn from(m: ModeFileType) -> u32 {
        match m {
            ModeFileType::Fifo => 0o010000,
            ModeFileType::Char => 0o020000,
            ModeFileType::Directory => 0o040000,
            ModeFileType::Block => 0o060000,
            ModeFileType::Regular => 0o100000,
            ModeFileType::NetworkSpecial => 0o110000,
            ModeFileType::Symlink => 0o120000,
            ModeFileType::Socket => 0o140000,
        }
    }
}

fn read_hex_u32<R: Read>(reader: &mut R) -> io::Result<u32> {
    let mut bytes = [0u8; 8];
    reader.read_exact(&mut bytes)?;
    ::std::str::from_utf8(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid utf-8 header field"))
        .and_then(|string| {
            u32::from_str_radix(string, 16).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "Invalid hex u32 header field")
            })
        })
}

impl CpioEntry {
    /// Returns the name of the file.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the inode number of the file. Sometimes this is just an index.
    pub fn ino(&self) -> u32 {
        self.ino
    }

    /// Returns the file's "mode" - the same as an inode "mode" field - containing permission bits
    /// and a bit of metadata about the type of file represented.
    pub fn mode(&self) -> u32 {
        self.mode
    }

    /// Returns the UID for this file's owner.
    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// Returns the GID for this file's group.
    pub fn gid(&self) -> u32 {
        self.gid
    }

    /// Returns the number of links associated with this file.
    pub fn nlink(&self) -> u32 {
        self.nlink
    }

    /// Returns the modification time of this file.
    pub fn mtime(&self) -> u32 {
        self.mtime
    }

    /// Returns the size of this file, in bytes.
    pub fn file_size(&self) -> u32 {
        self.file_size
    }

    /// Returns the major component of the device ID, describing the device on which this file
    /// resides.
    ///
    /// Device IDs are comprised of a major and minor component. The major component identifies
    /// the class of device, while the minor component identifies a specific device of that class.
    pub fn dev_major(&self) -> u32 {
        self.dev_major
    }

    /// Returns the minor component of the device ID, describing the device on which this file
    /// resides.
    ///
    /// Device IDs are comprised of a major and minor component. The major component identifies
    /// the class of device, while the minor component identifies a specific device of that class.
    pub fn dev_minor(&self) -> u32 {
        self.dev_minor
    }

    /// Returns the major component of the rdev ID, describes the device that this file
    /// (inode) represents.
    ///
    /// Device IDs are comprised of a major and minor component. The major component identifies
    /// the class of device, while the minor component identifies a specific device of that class.
    pub fn rdev_major(&self) -> u32 {
        self.rdev_major
    }

    /// Returns the minor component of the rdev ID, field describes the device that this file
    /// (inode) represents.
    ///
    /// Device IDs are comprised of a major and minor component. The major component identifies
    /// the class of device, while the minor component identifies a specific device of that class.
    pub fn rdev_minor(&self) -> u32 {
        self.rdev_minor
    }

    /// Returns true if this is a trailer entry.
    pub fn is_trailer(&self) -> bool {
        self.name == TRAILER_NAME
    }

    /// Return the checksum of this entry.
    ///
    /// The checksum is calculated by summing the bytes in the file and taking the least
    /// significant 32 bits. Not all CPIO archives use checksums.
    pub fn checksum(&self) -> Option<u32> {
        match self.entry_type {
            CpioEntryType::Crc => Some(self.checksum),
            CpioEntryType::Newc => None,
        }
    }
}

impl<R: Read> Reader<R> {
    /// Parses metadata for the next entry in an archive, and returns a reader
    /// that will yield the entry data.
    pub fn new(mut inner: R, file_entries: &[FileEntry]) -> io::Result<Reader<R>> {
        // char    c_magic[6];
        let mut magic = [0u8; 6];
        inner.read_exact(&mut magic)?;
        let entry = match magic.as_slice() {
            MAGIC_NUMBER_NEWASCII | MAGIC_NUMBER_NEWCRC => {
                let entry_type = match magic.as_slice() {
                    MAGIC_NUMBER_NEWASCII => CpioEntryType::Newc,
                    MAGIC_NUMBER_NEWCRC => CpioEntryType::Crc,
                    _ => unreachable!("can't happen"),
                };

                // char    c_ino[8];
                let ino = read_hex_u32(&mut inner)?;
                // char    c_mode[8];
                let mode = read_hex_u32(&mut inner)?;
                // char    c_uid[8];
                let uid = read_hex_u32(&mut inner)?;
                // char    c_gid[8];
                let gid = read_hex_u32(&mut inner)?;
                // char    c_nlink[8];
                let nlink = read_hex_u32(&mut inner)?;
                // char    c_mtime[8];
                let mtime = read_hex_u32(&mut inner)?;
                // char    c_filesize[8];
                let file_size = read_hex_u32(&mut inner)?;
                // char    c_devmajor[8];
                let dev_major = read_hex_u32(&mut inner)?;
                // char    c_devminor[8];
                let dev_minor = read_hex_u32(&mut inner)?;
                // char    c_rdevmajor[8];
                let rdev_major = read_hex_u32(&mut inner)?;
                // char    c_rdevminor[8];
                let rdev_minor = read_hex_u32(&mut inner)?;
                // char    c_namesize[8];
                let name_len = read_hex_u32(&mut inner)? as usize;
                // char    c_checksum[8];
                let checksum = read_hex_u32(&mut inner)?;

                // NUL-terminated name with length `name_len` (including NUL byte).
                let mut name_bytes = vec![0u8; name_len];
                if name_bytes.len() > 4096 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Entry name is too long",
                    ));
                }
                inner.read_exact(&mut name_bytes)?;
                if name_bytes.last() != Some(&0) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Entry name was not NUL-terminated",
                    ));
                }
                name_bytes.pop();
                // dracut-cpio sometimes pads the name to the next filesystem block.
                // See https://github.com/dracutdevs/dracut/commit/a9c67046
                while name_bytes.last() == Some(&0) {
                    name_bytes.pop();
                }
                let name = String::from_utf8(name_bytes).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "Entry name was not valid UTF-8")
                })?;

                // Pad out to a multiple of 4 bytes.
                if let Some(mut padding) = pad(HEADER_LEN + name_len) {
                    inner.read_exact(&mut padding)?;
                }
                let entry = CpioEntry {
                    entry_type,
                    name,
                    ino,
                    mode,
                    uid,
                    gid,
                    nlink,
                    mtime,
                    file_size,
                    dev_major,
                    dev_minor,
                    rdev_major,
                    rdev_minor,
                    checksum,
                };

                RpmPayloadEntry::Cpio(entry)
            }
            STRIPPED_CPIO_MAGIC_NUMBER => {
                // char    fx[8];
                let file_index = read_hex_u32(&mut inner)?;
                RpmPayloadEntry::Stripped(file_index)
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid magic number",
                ));
            }
        };

        let file_size: u64 = match entry {
            RpmPayloadEntry::Cpio(ref c) => c.file_size as u64,
            RpmPayloadEntry::Stripped(idx) => file_entries[idx as usize].size as u64,
        };

        Ok(Reader {
            inner,
            entry,
            file_size,
            bytes_read: 0,
        })
    }

    /// Returns the metadata for this entry.
    pub fn is_trailer(&self) -> bool {
        match &self.entry {
            RpmPayloadEntry::Cpio(c) => c.is_trailer(),
            RpmPayloadEntry::Stripped(idx) => *idx == u32::MAX,
        }
    }

    /// Finishes reading this entry and returns the underlying reader in a
    /// position ready to read the next entry (if any).
    pub fn finish(mut self) -> io::Result<R> {
        let remaining = self.file_size - self.bytes_read as u64;
        if remaining > 0 {
            io::copy(&mut self.inner.by_ref().take(remaining), &mut io::sink())?;
        }
        if let Some(mut padding) = pad(self.file_size as usize) {
            self.inner.read_exact(&mut padding)?;
        }
        Ok(self.inner)
    }
}

impl<R: Read> Read for Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.file_size as usize - self.bytes_read as usize;
        let limit = buf.len().min(remaining);
        if limit > 0 {
            let num_bytes = self.inner.read(&mut buf[..limit])?;
            self.bytes_read += num_bytes as u32;
            Ok(num_bytes)
        } else {
            Ok(0)
        }
    }
}

impl Builder {
    /// Create the metadata for one CPIO entry
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            ino: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            nlink: 1,
            mtime: 0,
            dev_major: 0,
            dev_minor: 0,
            rdev_major: 0,
            rdev_minor: 0,
        }
    }

    /// Set the inode number for this file. In modern times however, typically this is just a
    /// a unique index ID for the file, rather than the actual inode number.
    pub fn ino(mut self, ino: u32) -> Self {
        self.ino = ino;
        self
    }

    /// Set the file's "mode" - the same as an inode "mode" field - containing permission bits
    /// and a bit of metadata about the type of file represented.
    pub fn mode(mut self, mode: u32) -> Self {
        self.mode = mode;
        self
    }

    /// Set this file's UID.
    pub fn uid(mut self, uid: u32) -> Self {
        self.uid = uid;
        self
    }

    /// Set this file's GID.
    pub fn gid(mut self, gid: u32) -> Self {
        self.gid = gid;
        self
    }

    /// Set the number of links associated with this file.
    pub fn nlink(mut self, nlink: u32) -> Self {
        self.nlink = nlink;
        self
    }

    /// Set the modification time of this file.
    pub fn mtime(mut self, mtime: u32) -> Self {
        self.mtime = mtime;
        self
    }

    /// Set the major component of the device ID, describing the device on which this file
    /// resides.
    ///
    /// Device IDs are comprised of a major and minor component. The major component identifies
    /// the class of device, while the minor component identifies a specific device of that class.
    pub fn dev_major(mut self, dev_major: u32) -> Self {
        self.dev_major = dev_major;
        self
    }

    /// Set the minor component of the device ID, describing the device on which this file
    /// resides.
    ///
    /// Device IDs are comprised of a major and minor component. The major component identifies
    /// the class of device, while the minor component identifies a specific device of that class.
    pub fn dev_minor(mut self, dev_minor: u32) -> Self {
        self.dev_minor = dev_minor;
        self
    }

    /// Set the major component of the rdev ID, describes the device that this file
    /// (inode) represents.
    ///
    /// Device IDs are comprised of a major and minor component. The major component identifies
    /// the class of device, while the minor component identifies a specific device of that class.
    pub fn rdev_major(mut self, rdev_major: u32) -> Self {
        self.rdev_major = rdev_major;
        self
    }

    /// Set the minor component of the rdev ID, field describes the device that this file
    /// (inode) represents.
    ///
    /// Device IDs are comprised of a major and minor component. The major component identifies
    /// the class of device, while the minor component identifies a specific device of that class.
    pub fn rdev_minor(mut self, rdev_minor: u32) -> Self {
        self.rdev_minor = rdev_minor;
        self
    }

    /// Set the mode file type of the entry
    pub fn set_mode_file_type(mut self, file_type: ModeFileType) -> Self {
        self.mode &= !ModeFileType::MASK;
        self.mode |= u32::from(file_type);
        self
    }

    /// Write out an entry to the provided writer in SVR4 "new ascii" CPIO format.
    pub fn write_cpio<W: Write>(self, w: W, file_size: u32) -> Writer<W> {
        let header = self.into_header(file_size, None);

        Writer {
            inner: w,
            written: 0,
            file_size,
            header_size: header.len(),
            header,
        }
    }

    /// Write out an entry to the provided writer in SVR4 "new crc" CPIO format.
    pub fn write_crc<W: Write>(self, w: W, file_size: u32, file_checksum: u32) -> Writer<W> {
        let header = self.into_header(file_size, Some(file_checksum));

        Writer {
            inner: w,
            written: 0,
            file_size,
            header_size: header.len(),
            header,
        }
    }

    /// Build a newc header from the entry metadata.
    fn into_header(self, file_size: u32, file_checksum: Option<u32>) -> Vec<u8> {
        let mut header = Vec::with_capacity(HEADER_LEN);

        // char    c_magic[6];
        if file_checksum.is_some() {
            header.extend(MAGIC_NUMBER_NEWCRC);
        } else {
            header.extend(MAGIC_NUMBER_NEWASCII);
        }
        // char    c_ino[8];
        header.extend(format!("{:08x}", self.ino).as_bytes());
        // char    c_mode[8];
        header.extend(format!("{:08x}", self.mode).as_bytes());
        // char    c_uid[8];
        header.extend(format!("{:08x}", self.uid).as_bytes());
        // char    c_gid[8];
        header.extend(format!("{:08x}", self.gid).as_bytes());
        // char    c_nlink[8];
        header.extend(format!("{:08x}", self.nlink).as_bytes());
        // char    c_mtime[8];
        header.extend(format!("{:08x}", self.mtime).as_bytes());
        // char    c_filesize[8];
        header.extend(format!("{:08x}", file_size).as_bytes());
        // char    c_devmajor[8];
        header.extend(format!("{:08x}", self.dev_major).as_bytes());
        // char    c_devminor[8];
        header.extend(format!("{:08x}", self.dev_minor).as_bytes());
        // char    c_rdevmajor[8];
        header.extend(format!("{:08x}", self.rdev_major).as_bytes());
        // char    c_rdevminor[8];
        header.extend(format!("{:08x}", self.rdev_minor).as_bytes());
        // char    c_namesize[8];
        let name_len = self.name.len() + 1;
        header.extend(format!("{:08x}", name_len).as_bytes());
        // char    c_check[8];
        header.extend(format!("{:08x}", file_checksum.unwrap_or(0)).as_bytes());

        // append the name to the end of the header
        header.extend(self.name.as_bytes());
        header.push(0u8);

        // pad out to a multiple of 4 bytes
        if let Some(pad) = pad(HEADER_LEN + name_len) {
            header.extend(pad);
        }

        header
    }
}

/// Build a stripped archive header
pub fn stripped_cpio_header(file_index: u32) -> Vec<u8> {
    let mut header = Vec::with_capacity(STRIPPED_CPIO_HEADER_LEN);

    // char    c_magic[6];
    header.extend(STRIPPED_CPIO_MAGIC_NUMBER);

    // char    fx[8];  (file index)
    header.extend(format!("{:08x}", file_index).as_bytes());

    // pad out to a multiple of 4 bytes
    if let Some(pad) = pad(STRIPPED_CPIO_HEADER_LEN) {
        header.extend(pad);
    }

    header
}

impl<W: Write> Writer<W> {
    pub fn finish(mut self) -> io::Result<W> {
        self.do_finish()?;
        Ok(self.inner)
    }

    fn try_write_header(&mut self) -> io::Result<()> {
        if !self.header.is_empty() {
            self.inner.write_all(&self.header)?;
            self.header.truncate(0);
        }
        Ok(())
    }

    fn do_finish(&mut self) -> io::Result<()> {
        self.try_write_header()?;

        if self.written == self.file_size {
            if let Some(pad) = pad(self.header_size + self.file_size as usize) {
                self.inner.write_all(&pad)?;
                self.inner.flush()?;
            }
        }

        Ok(())
    }
}

impl<W: Write> Write for Writer<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.written + buf.len() as u32 <= self.file_size {
            self.try_write_header()?;

            let n = self.inner.write(buf)?;
            self.written += n as u32;
            Ok(n)
        } else {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "trying to write more than the specified file size",
            ))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Writes a trailer entry into an archive.
pub fn trailer<W: Write>(w: W) -> io::Result<W> {
    let b = Builder::new(TRAILER_NAME).nlink(1);
    let writer = b.write_cpio(w, 0);
    writer.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, copy};

    fn entry<R: Read>(reader: &Reader<R>) -> &CpioEntry {
        match reader.entry {
            RpmPayloadEntry::Cpio(ref cpio) => cpio,
            _ => unreachable!(),
        }
    }

    #[test]
    fn test_single_file() {
        // Set up our input file
        let data: &[u8] = b"Hello, World";
        let length = data.len() as u32;
        let mut input = Cursor::new(data);

        // Set up our output file
        let output = vec![];

        // Set up the descriptor of our input file
        let b = Builder::new("./hello_world");
        // and get a writer for that input file
        let mut writer = b.write_cpio(output, length);

        // Copy the input file into our CPIO archive
        copy(&mut input, &mut writer).unwrap();
        let output = writer.finish().unwrap();

        // Finish up by writing the trailer for the archive
        let output = trailer(output).unwrap();

        // Now read the archive back in and make sure we get the same data.
        let mut reader = Reader::new(output.as_slice(), &[]).unwrap();
        assert_eq!(entry(&reader).name(), "./hello_world");
        assert_eq!(entry(&reader).file_size(), length);
        let mut contents = vec![];
        copy(&mut reader, &mut contents).unwrap();
        assert_eq!(contents, data);
        let reader = Reader::new(reader.finish().unwrap(), &[]).unwrap();
        assert!(entry(&reader).is_trailer());
    }

    #[test]
    fn test_multi_file() {
        // Set up our input files
        let data1: &[u8] = b"Hello, World";
        let length1 = data1.len() as u32;
        let mut input1 = Cursor::new(data1);

        let data2: &[u8] = b"Hello, World 2";
        let length2 = data2.len() as u32;
        let mut input2 = Cursor::new(data2);

        // Set up our output file
        let output = vec![];

        // Set up the descriptor of our input file
        let b = Builder::new("./hello_world")
            .ino(1)
            .uid(1000)
            .gid(1000)
            .mode(0o100644);
        // and get a writer for that input file
        let mut writer = b.write_cpio(output, length1);

        // Copy the input file into our CPIO archive
        copy(&mut input1, &mut writer).unwrap();
        let output = writer.finish().unwrap();

        // Set up the descriptor of our second input file
        let b = Builder::new("./hello_world2")
            .ino(2)
            .uid(1000)
            .gid(1000)
            .mode(0o100644);
        // and get a writer for that input file
        let mut writer = b.write_cpio(output, length2);

        // Copy the second input file into our CPIO archive
        copy(&mut input2, &mut writer).unwrap();
        let output = writer.finish().unwrap();

        // Finish up by writing the trailer for the archive
        let output = trailer(output).unwrap();

        // Now read the archive back in and make sure we get the same data.
        let mut reader = Reader::new(output.as_slice(), &[]).unwrap();
        assert_eq!(entry(&reader).name(), "./hello_world");
        assert_eq!(entry(&reader).file_size(), length1);
        assert_eq!(entry(&reader).ino(), 1);
        assert_eq!(entry(&reader).uid(), 1000);
        assert_eq!(entry(&reader).gid(), 1000);
        assert_eq!(entry(&reader).mode(), 0o100644);
        let mut contents = vec![];
        copy(&mut reader, &mut contents).unwrap();
        assert_eq!(contents, data1);

        let mut reader = Reader::new(reader.finish().unwrap(), &[]).unwrap();
        assert_eq!(entry(&reader).name(), "./hello_world2");
        assert_eq!(entry(&reader).file_size(), length2);
        assert_eq!(entry(&reader).ino(), 2);
        let mut contents = vec![];
        copy(&mut reader, &mut contents).unwrap();
        assert_eq!(contents, data2);

        let reader = Reader::new(reader.finish().unwrap(), &[]).unwrap();
        assert!(reader.is_trailer());
    }
}
