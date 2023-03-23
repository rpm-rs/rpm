// This code is copied from the crate `cpio-rs` by Jonathan Creekmore (https://github.com/jcreekmore/cpio-rs)
// under the MIT license.
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

//! Read/write `newc` (SVR4) format archives.

use std::io::{self, Read, Write};

const HEADER_LEN: usize = 110;

const MAGIC_NUMBER: &[u8] = b"070701";

const TRAILER_NAME: &str = "TRAILER!!!";

/// Metadata about one entry from an archive.
pub struct Entry {
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
}

/// Reads one entry header/data from an archive.
pub struct Reader<R: Read> {
    inner: R,
    entry: Entry,
    bytes_read: u32,
}

/// Builds metadata for one entry to be written into an archive.
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

impl Entry {
    /// Returns the name of the file.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the inode number of the file.
    pub fn ino(&self) -> u32 {
        self.ino
    }

    /// Returns the permission bits of the file.
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

    pub fn dev_major(&self) -> u32 {
        self.dev_major
    }

    pub fn dev_minor(&self) -> u32 {
        self.dev_minor
    }

    pub fn rdev_major(&self) -> u32 {
        self.rdev_major
    }

    pub fn rdev_minor(&self) -> u32 {
        self.rdev_minor
    }

    /// Returns true if this is a trailer entry.
    pub fn is_trailer(&self) -> bool {
        self.name == TRAILER_NAME
    }
}

impl<R: Read> Reader<R> {
    /// Parses metadata for the next entry in an archive, and returns a reader
    /// that will yield the entry data.
    pub fn new(mut inner: R) -> io::Result<Reader<R>> {
        // char    c_magic[6];
        let mut magic = [0u8; 6];
        inner.read_exact(&mut magic)?;
        if magic != MAGIC_NUMBER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid magic number",
            ));
        }
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
        let _checksum = read_hex_u32(&mut inner)?;

        // NUL-terminated name with length `name_len` (including NUL byte).
        let mut name_bytes = vec![0u8; name_len];
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

        let entry = Entry {
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
        };
        Ok(Reader {
            inner,
            entry,
            bytes_read: 0,
        })
    }

    /// Returns the metadata for this entry.
    pub fn entry(&self) -> &Entry {
        &self.entry
    }

    /// Finishes reading this entry and returns the underlying reader in a
    /// position ready to read the next entry (if any).
    pub fn finish(mut self) -> io::Result<R> {
        let remaining = self.entry.file_size - self.bytes_read;
        if remaining > 0 {
            io::copy(
                &mut self.inner.by_ref().take(remaining as u64),
                &mut io::sink(),
            )?;
        }
        if let Some(mut padding) = pad(self.entry.file_size as usize) {
            self.inner.read_exact(&mut padding)?;
        }
        Ok(self.inner)
    }
}

impl<R: Read> Read for Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.entry.file_size - self.bytes_read;
        let limit = buf.len().min(remaining as usize);
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
    pub fn new(name: &str) -> Builder {
        Builder {
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

    pub fn ino(mut self, ino: u32) -> Builder {
        self.ino = ino;
        self
    }

    pub fn mode(mut self, mode: u32) -> Builder {
        self.mode = mode;
        self
    }

    pub fn uid(mut self, uid: u32) -> Builder {
        self.uid = uid;
        self
    }

    pub fn gid(mut self, gid: u32) -> Builder {
        self.gid = gid;
        self
    }

    pub fn nlink(mut self, nlink: u32) -> Builder {
        self.nlink = nlink;
        self
    }

    pub fn mtime(mut self, mtime: u32) -> Builder {
        self.mtime = mtime;
        self
    }

    pub fn dev_major(mut self, dev_major: u32) -> Builder {
        self.dev_major = dev_major;
        self
    }

    pub fn dev_minor(mut self, dev_minor: u32) -> Builder {
        self.dev_minor = dev_minor;
        self
    }

    pub fn rdev_major(mut self, rdev_major: u32) -> Builder {
        self.rdev_major = rdev_major;
        self
    }

    pub fn rdev_minor(mut self, rdev_minor: u32) -> Builder {
        self.rdev_minor = rdev_minor;
        self
    }

    pub fn write<W: Write>(self, w: W, file_size: u32) -> Writer<W> {
        let header = self.into_header(file_size);

        Writer {
            inner: w,
            written: 0,
            file_size: file_size,
            header_size: header.len(),
            header: header,
        }
    }

    fn into_header(self, file_size: u32) -> Vec<u8> {
        let mut header = Vec::with_capacity(HEADER_LEN);

        // char    c_magic[6];
        header.extend(MAGIC_NUMBER);
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
        header.extend(format!("{:08x}", 0).as_bytes());

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

impl<W: Write> Writer<W> {
    pub fn finish(mut self) -> io::Result<W> {
        self.do_finish()?;
        Ok(self.inner)
    }

    fn try_write_header(&mut self) -> io::Result<()> {
        if self.header.len() != 0 {
            self.inner.write_all(&self.header)?;
            self.header.truncate(0);
        }
        Ok(())
    }

    fn do_finish(&mut self) -> io::Result<()> {
        self.try_write_header()?;

        if self.written == self.file_size {
            if let Some(pad) = pad(self.header_size + self.file_size as usize) {
                self.inner.write(&pad)?;
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
    let writer = b.write(w, 0);
    writer.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{copy, Cursor};

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
        let mut writer = b.write(output, length);

        // Copy the input file into our CPIO archive
        copy(&mut input, &mut writer).unwrap();
        let output = writer.finish().unwrap();

        // Finish up by writing the trailer for the archive
        let output = trailer(output).unwrap();

        // Now read the archive back in and make sure we get the same data.
        let mut reader = Reader::new(output.as_slice()).unwrap();
        assert_eq!(reader.entry.name(), "./hello_world");
        assert_eq!(reader.entry.file_size(), length);
        let mut contents = vec![];
        copy(&mut reader, &mut contents).unwrap();
        assert_eq!(contents, data);
        let reader = Reader::new(reader.finish().unwrap()).unwrap();
        assert!(reader.entry().is_trailer());
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
        let mut writer = b.write(output, length1);

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
        let mut writer = b.write(output, length2);

        // Copy the second input file into our CPIO archive
        copy(&mut input2, &mut writer).unwrap();
        let output = writer.finish().unwrap();

        // Finish up by writing the trailer for the archive
        let output = trailer(output).unwrap();

        // Now read the archive back in and make sure we get the same data.
        let mut reader = Reader::new(output.as_slice()).unwrap();
        assert_eq!(reader.entry().name(), "./hello_world");
        assert_eq!(reader.entry().file_size(), length1);
        assert_eq!(reader.entry().ino(), 1);
        assert_eq!(reader.entry().uid(), 1000);
        assert_eq!(reader.entry().gid(), 1000);
        assert_eq!(reader.entry().mode(), 0o100644);
        let mut contents = vec![];
        copy(&mut reader, &mut contents).unwrap();
        assert_eq!(contents, data1);

        let mut reader = Reader::new(reader.finish().unwrap()).unwrap();
        assert_eq!(reader.entry().name(), "./hello_world2");
        assert_eq!(reader.entry().file_size(), length2);
        assert_eq!(reader.entry().ino(), 2);
        let mut contents = vec![];
        copy(&mut reader, &mut contents).unwrap();
        assert_eq!(contents, data2);

        let reader = Reader::new(reader.finish().unwrap()).unwrap();
        assert!(reader.entry().is_trailer());
    }
}
