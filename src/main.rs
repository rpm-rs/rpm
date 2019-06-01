use nom;
use quick_xml::events::Event;
use quick_xml::Reader;
use std::fmt;
use std::io;

use enum_display_derive;
use nom::bytes::complete;
use nom::number::complete::{be_i16, be_i32, be_i64, be_i8, be_u16, be_u32, be_u8};
use num;
use num_derive;
use std::convert::TryInto;
use std::fmt::Display;

fn main() {
    println!("Hello, world!");
}

struct RepoMD {
    revision: u64,
    data: Vec<RepoMDData>,
}

impl RepoMD {}

struct RepoMDData {
    data_type: String,
    checksum: Checksum,
    location: String,
    timestamp: u64,
    size: u64,
    open_size: u64,
}

struct Checksum {
    checksum_type: ChecksumType,
    value: String,
    pkgid: Option<bool>,
}

enum ChecksumType {
    SHA256,
    SHA1,
    MD5,
}

enum DataType {
    Group,
    GroupGZ,
    FileLists,
    FileListsDB,
    Primary,
    PrimaryDB,
    OtherDB,
    Other,
}

struct OtherData {
    num_packages: u64,
}

struct OtherDataPackage {
    pkgid: String,
    name: String,
    arch: String,
    version: Version,
    changelog: Vec<ChangelogEntry>,
}

struct Version {
    epoch: String,
    ver: String,
    rel: String,
}

struct ChangelogEntry {
    author: String,
    date: u64,
    description: String,
}

struct Metadata {
    packages: u64,
}

struct PrimaryPackage {
    package_type: PackageType,
    name: String,
    arch: Arch,
    checksum: Checksum,
    summary: String,
    description: String,
    packager: String,
    url: String,
    file_time: u64,
    build_time: u64,
    package_size: u64,
    installed_size: u64,
    archived_size: u64,
    location: String,
    format: RpmFormat,
}

enum PackageType {
    RPM,
}
enum Arch {
    X86_64,
}

struct RpmFormat {
    license: String,
    vendor: String,
    group: String,
    buildhost: String,
    sourcerpm: String,
    header_range: HeaderRange,
    provides: Vec<RpmEntry>,
    requires: Vec<RpmEntry>,
    conflicts: Vec<RpmEntry>,
    obsoletes: Vec<RpmEntry>,
    files: Vec<String>,
    dirs: Vec<String>,
}

struct RpmEntry {
    name: String,
    flags: Option<EntryFlag>,
    epoch: Option<String>,
    ver: Option<String>,
    rel: Option<String>,
}

enum EntryFlag {
    EQ,
    GE,
}

struct HeaderRange {
    start: u64,
    end: u64,
}

const LEAD_SIZE: usize = 96;
const RPM_MAGIC: [u8; 4] = [0xed, 0xab, 0xee, 0xdb];

const HEADER_MAGIC: [u8; 3] = [0x8e, 0xad, 0xe8];

struct RPMPackage {
    metadata: RPMPackageMetadata,
    content: Vec<u8>,
}

impl RPMPackage {
    fn parse<T: std::io::BufRead>(input: &mut T) -> Result<Self, RPMError> {
        let metadata = RPMPackageMetadata::parse(input)?;
        let mut content = Vec::new();
        input.read_to_end(&mut content)?;
        Ok(RPMPackage {
            metadata: metadata,
            content: content,
        })
    }

    fn write<W: std::io::Write>(&self, out: &mut W) -> Result<(), RPMError> {
        self.metadata.write(out)?;
        out.write_all(&self.content)?;
        Ok(())
    }
}
#[derive(PartialEq)]
struct RPMPackageMetadata {
    lead: Lead,
    signature: Header<IndexSignatureTag>,
    header: Header<IndexTag>,
}

impl RPMPackageMetadata {
    fn parse<T: std::io::BufRead>(input: &mut T) -> Result<Self, RPMError> {
        let mut lead_buffer = [0; LEAD_SIZE];
        input.read_exact(&mut lead_buffer)?;
        let lead = Lead::parse(&lead_buffer)?;
        let signature_header = Header::parse_signature(input)?;
        let header = Header::parse(input)?;
        Ok(RPMPackageMetadata {
            lead: lead,
            signature: signature_header,
            header: header,
        })
    }

    fn write<W: std::io::Write>(&self, out: &mut W) -> Result<(), RPMError> {
        self.lead.write(out)?;
        self.signature.write_signature(out)?;
        self.header.write(out)?;
        Ok(())
    }
}

struct Lead {
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
    fn parse(mut input: &[u8]) -> Result<Self, RPMError> {
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
            major: major,
            minor: minor,
            package_type: pkg_type,
            arch: arch,
            name: name_arr,
            os: os,
            signature_type: sigtype,
            reserved: rest.try_into().unwrap(),
        })
    }

    fn write<W: std::io::Write>(&self, out: &mut W) -> Result<(), RPMError> {
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

#[derive(Debug, PartialEq)]
struct Header<T: num::FromPrimitive> {
    index_header: IndexHeader,
    index_entries: Vec<IndexEntry<T>>,
}

impl<T> Header<T>
where
    T: num::FromPrimitive + num::ToPrimitive + PartialEq + Display + std::fmt::Debug,
{
    fn parse<I: std::io::BufRead>(input: &mut I) -> Result<Header<T>, RPMError> {
        let mut buf: [u8; 16] = [0; 16];
        input.read_exact(&mut buf)?;
        let index_header = IndexHeader::parse(&buf)?;
        // read rest of header => each index consists of 16 bytes. The index header knows how large the store is.
        let mut buf = vec![0; (index_header.header_size + index_header.num_entries * 16) as usize];
        input.read_exact(&mut buf)?;

        // parse all entries
        let mut entries: Vec<IndexEntry<T>> = Vec::new();
        let mut bytes = &buf[..];
        let mut buf_len = bytes.len();
        for _ in 0..index_header.num_entries {
            let (rest, entry) = IndexEntry::parse(bytes)?;
            entries.push(entry);
            bytes = rest;
            assert_eq!(16, buf_len - bytes.len());
            buf_len = bytes.len();
        }

        assert_eq!(bytes.len(), index_header.header_size as usize);

        // add data to entries
        for mut entry in &mut entries {
            let mut remaining = &bytes[entry.offset as usize..];
            match &mut entry.data {
                IndexData::Null => {}
                IndexData::Char(ref mut chars) => {
                    parse_entry_data_number(remaining, entry.num_items, chars, be_u8)?;
                }
                IndexData::Int8(ref mut ints) => {
                    parse_entry_data_number(remaining, entry.num_items, ints, be_i8)?.0;
                }
                IndexData::Int16(ref mut ints) => {
                    parse_entry_data_number(remaining, entry.num_items, ints, be_i16)?.0;
                }
                IndexData::Int32(ref mut ints) => {
                    parse_entry_data_number(remaining, entry.num_items, ints, be_i32)?.0;
                }
                IndexData::Int64(ref mut ints) => {
                    parse_entry_data_number(remaining, entry.num_items, ints, be_i64)?.0;
                }
                IndexData::StringTag(ref mut string) => {
                    let (rest, raw_string) = complete::take_till(|item| item == b'\0')(remaining)?;
                    string.push_str(String::from_utf8_lossy(raw_string).as_ref());
                }
                IndexData::Bin(ref mut bin) => {
                    parse_entry_data_number(remaining, entry.num_items, bin, be_u8)?;
                }
                IndexData::StringArray(ref mut strings) => {
                    for _ in 0..entry.num_items {
                        let (rest, raw_string) = complete::take_till(|item| item == 0)(remaining)?;
                        let (_, zeros) = complete::take_while(|item| item == 0)(rest)?;
                        remaining = &rest[1..];
                        let string = String::from_utf8_lossy(raw_string).to_string();
                        strings.push(string);
                    }
                }
                IndexData::I18NString(ref mut strings) => {
                    for _ in 0..entry.num_items {
                        let (rest, raw_string) = complete::take_till(|item| item == 0)(remaining)?;
                        remaining = rest;
                        let string = String::from_utf8_lossy(raw_string).to_string();
                        strings.push(string);
                    }
                }
            }
        }

        Ok(Header {
            index_header: index_header,
            index_entries: entries,
        })
    }

    fn write<W: std::io::Write>(&self, out: &mut W) -> Result<(), RPMError> {
        self.index_header.write(out)?;
        let mut store_buf = vec![0; self.index_header.header_size as usize];

        for entry in &self.index_entries {
            entry.write(out, &mut store_buf);
        }
        out.write_all(&store_buf)?;
        Ok(())
    }

    fn find_entry(&self, tag: T) -> Option<&IndexEntry<T>> {
        for entry in &self.index_entries {
            if entry.tag == tag {
                return Some(entry);
            }
        }
        None
    }

    fn find_entry_or_err(&self, tag: &T) -> Result<&IndexEntry<T>, RPMError> {
        for entry in &self.index_entries {
            if &entry.tag == tag {
                return Ok(entry);
            }
        }
        Err(RPMError::new(&format!("unable to find Tag {}", tag)))
    }

    fn get_entry_string_data(&self, tag: T) -> Result<&str, RPMError> {
        let entry = self.find_entry_or_err(&tag)?;
        entry.data.string().ok_or(RPMError::new(&format!(
            "tag {} has datatype {}, not string",
            entry.tag, entry.data,
        )))
    }

    fn get_entry_string_array_data(&self, tag: T) -> Result<&[String], RPMError> {
        let entry = self.find_entry_or_err(&tag)?;
        entry.data.string_array().ok_or(RPMError::new(&format!(
            "tag {} does not provide string array",
            entry.tag,
        )))
    }
}

impl Header<IndexSignatureTag> {
    fn parse_signature<I: std::io::BufRead>(
        input: &mut I,
    ) -> Result<Header<IndexSignatureTag>, RPMError> {
        let mut result = Self::parse(input)?;
        // this structure is aligned to 8 bytes - rest is filled up with zeros.
        // if the size of our store is not a modulo of 8, we discard bytes to align to the 8 byte boundary.
        let modulo = result.index_header.header_size % 8;
        if modulo > 0 {
            let align_size = 8 - modulo;
            let mut discard = vec![0; align_size as usize];
            input.read_exact(&mut discard)?;
        }
        Ok(result)
    }

    fn write_signature<W: std::io::Write>(&self, out: &mut W) -> Result<(), RPMError> {
        self.write(out)?;
        let modulo = self.index_header.header_size % 8;
        if modulo > 0 {
            let mut expansion = vec![0; 8 - modulo as usize];
            out.write_all(&mut expansion)?;
        }
        Ok(())
    }
}

impl Header<IndexTag> {
    fn get_payload_format(&self) -> Result<&str, RPMError> {
        self.get_entry_string_data(IndexTag::RPMTAG_PAYLOADFORMAT)
    }

    fn get_payload_compressor(&self) -> Result<&str, RPMError> {
        self.get_entry_string_data(IndexTag::RPMTAG_PAYLOADCOMPRESSOR)
    }

    fn get_file_checksums(&self) -> Result<&[String], RPMError> {
        self.get_entry_string_array_data(IndexTag::RPMTAG_FILEDIGESTS)
    }
}

#[derive(Debug, PartialEq)]
struct IndexHeader {
    magic: [u8; 3],
    version: u8,
    num_entries: u32,
    header_size: u32,
}

impl IndexHeader {
    // 16 bytes
    fn parse(input: &[u8]) -> Result<Self, RPMError> {
        // first three bytes are magic
        let (rest, magic) = complete::take(3usize)(input)?;
        for i in 0..2 {
            if HEADER_MAGIC[i] != magic[i] {
                return Err(RPMError::new(&format!(
                    "invalid magic {} vs {} - whole input was {:x?}",
                    HEADER_MAGIC[i], magic[i], input,
                )));
            }
        }

        // then version
        let (rest, version) = be_u8(rest)?;

        if version != 1 {
            return Err(RPMError::new(&format!(
                "unsupported Versionv {} - only header version 1 is supported",
                version,
            )));
        }
        // then reserved
        let (rest, _) = complete::take(4usize)(rest)?;
        // then number of of entries
        let (rest, num_entries) = be_u32(rest)?;
        // then size of header
        let (rest, header_size) = be_u32(rest)?;

        Ok(IndexHeader {
            magic: magic.try_into().unwrap(),
            version: 1,
            num_entries: num_entries,
            header_size: header_size,
        })
    }

    fn write<W: std::io::Write>(&self, out: &mut W) -> Result<(), RPMError> {
        out.write_all(&self.magic)?;
        out.write_all(&self.version.to_be_bytes())?;
        out.write_all(&[0; 4]);
        out.write_all(&self.num_entries.to_be_bytes())?;
        out.write_all(&self.header_size.to_be_bytes())?;
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
struct IndexEntry<T: num::FromPrimitive> {
    tag: T,
    data: IndexData,
    offset: u32,
    num_items: u32,
}

impl<T: num::FromPrimitive + num::ToPrimitive> IndexEntry<T> {
    // 16 bytes
    fn parse(input: &[u8]) -> Result<(&[u8], Self), RPMError> {
        //first 4 bytes are the tag.
        let (input, raw_tag) = be_u32(input)?;

        let tag: T = num::FromPrimitive::from_u32(raw_tag)
            .ok_or(RPMError::new(&format!("invalid tag {}", raw_tag)))?;
        //next 4 bytes is the tag type
        let (input, raw_tag_type) = be_u32(input)?;

        // initialize the datatype. Parsing of the data happens later since the store comes after the index section.
        let data = IndexData::from_u32(raw_tag_type)
            .ok_or(RPMError::new(&format!("invalid tag_type {}", raw_tag_type)))?;

        //  next 4 bytes is the offset relative to the beginning of the store
        let (input, offset) = be_u32(input)?;

        // last 4 bytes are the count that contains the number of data items pointed to by the index entry
        let (rest, num_items) = be_u32(input)?;

        Ok((
            rest,
            IndexEntry {
                tag: tag,
                data: data,
                offset: offset,
                num_items: num_items,
            },
        ))
    }

    fn write<W: std::io::Write>(&self, out: &mut W, store: &mut [u8]) -> Result<(), RPMError> {
        // write index into the writer direct and the data into the store. the store will be flushed after it has been finalized
        let mut written = out.write(&self.tag.to_u32().unwrap().to_be_bytes())?;
        let mut raw_datatype: u32 = 0;
        match &self.data {
            IndexData::Null => {}
            IndexData::Char(d) => {
                raw_datatype = 1;
                for i in 0..d.len() {
                    store[self.offset as usize + i] = d[i];
                }
            }
            IndexData::Int8(d) => {
                raw_datatype = 2;
                for i in 0..d.len() {
                    store[self.offset as usize + i] = d[i].to_be_bytes()[0];
                }
            }
            IndexData::Int16(d) => {
                raw_datatype = 3;
                let mut iter = d.iter().flat_map(|item| item.to_be_bytes().to_vec());
                for (i, byte) in iter.enumerate() {
                    store[self.offset as usize + i] = byte;
                }
            }
            IndexData::Int32(d) => {
                raw_datatype = 4;
                let mut iter = d.iter().flat_map(|item| item.to_be_bytes().to_vec());
                for (i, byte) in iter.enumerate() {
                    store[self.offset as usize + i] = byte;
                }
            }
            IndexData::Int64(d) => {
                raw_datatype = 5;
                let mut iter = d.iter().flat_map(|item| item.to_be_bytes().to_vec());
                for (i, byte) in iter.enumerate() {
                    store[self.offset as usize + i] = byte;
                }
            }
            IndexData::StringTag(d) => {
                raw_datatype = 6;
                append_string(d, self.offset as usize, store);
            }
            IndexData::Bin(d) => {
                raw_datatype = 7;
                for i in 0..d.len() {
                    store[self.offset as usize + i] = d[i];
                }
            }
            IndexData::StringArray(d) => {
                raw_datatype = 8;
                let mut offset = self.offset;

                for item in d {
                    append_string(item, offset as usize, store);
                    offset = offset + item.len() as u32 + 1;
                }
            }
            IndexData::I18NString(d) => {
                raw_datatype = 9;

                let mut offset = self.offset;

                for item in d {
                    append_string(item, offset as usize, store);
                    offset = offset + item.len() as u32 + 1;
                }
            }
        }
        written += out.write(&raw_datatype.to_be_bytes())?;
        written += out.write(&self.offset.to_be_bytes())?;
        written += out.write(&self.num_items.to_be_bytes())?;
        assert_eq!(16, written, "there should be 16 bytes written");
        Ok(())
    }
}

fn append_string(data: &str, offset: usize, store: &mut [u8]) {
    let mut iter = data.bytes();
    let mut index = 0;
    for byte in iter {
        store[offset + index] = byte;
        index += 1;
    }
    store[offset + index] = 0;
}

#[derive(Debug, PartialEq, Eq)]
enum IndexData {
    Null,
    Char(Vec<u8>),
    Int8(Vec<i8>),
    Int16(Vec<i16>),
    Int32(Vec<i32>),
    Int64(Vec<i64>),
    StringTag(String),
    Bin(Vec<u8>),
    StringArray(Vec<String>),
    I18NString(Vec<String>),
}

impl Display for IndexData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let rep = match self {
            IndexData::Null => "Null",
            IndexData::Bin(_) => "Bin",
            IndexData::Char(_) => "Char",
            IndexData::I18NString(_) => "I18NString",
            IndexData::StringTag(_) => "String",
            IndexData::StringArray(_) => "StringArray",
            IndexData::Int8(_) => "i8",
            IndexData::Int16(_) => "i16",
            IndexData::Int32(_) => "i32",
            IndexData::Int64(_) => "i64",
        };
        write!(f, "{}", rep)
    }
}

impl IndexData {
    fn from_u32(i: u32) -> Option<Self> {
        match i {
            0 => Some(IndexData::Null),
            1 => Some(IndexData::Char(Vec::new())),
            2 => Some(IndexData::Int8(Vec::new())),
            3 => Some(IndexData::Int16(Vec::new())),
            4 => Some(IndexData::Int32(Vec::new())),
            5 => Some(IndexData::Int64(Vec::new())),
            6 => Some(IndexData::StringTag(String::new())),
            7 => Some(IndexData::Bin(Vec::new())),
            8 => Some(IndexData::StringArray(Vec::new())),
            9 => Some(IndexData::I18NString(Vec::new())),
            _ => None,
        }
    }
    fn string(&self) -> Option<&str> {
        match self {
            IndexData::StringTag(s) => Some(&s),
            _ => None,
        }
    }

    fn string_array(&self) -> Option<&[String]> {
        match self {
            IndexData::StringArray(d) | IndexData::I18NString(d) => Some(&d),
            _ => None,
        }
    }
}

const HEADER_IMAGE: isize = 61;
const HEADER_SIGNATURES: isize = 62;
const HEADER_IMMUTABLE: isize = 63;
const HEADER_REGIONS: isize = 64;
const HEADER_I18NTABLE: isize = 100;
const HEADER_SIGBASE: isize = 256;
const HEADER_TAGBASE: isize = 1000;
const RPMTAG_SIG_BASE: isize = HEADER_SIGBASE;

#[derive(
    num_derive::FromPrimitive,
    num_derive::ToPrimitive,
    Debug,
    PartialEq,
    enum_display_derive::Display,
)]
enum IndexTag {
    RPMTAG_HEADERIMAGE = HEADER_IMAGE,
    RPMTAG_HEADERSIGNATURES = HEADER_SIGNATURES,
    RPMTAG_HEADERIMMUTABLE = HEADER_IMMUTABLE,
    RPMTAG_HEADERREGIONS = HEADER_REGIONS,

    RPMTAG_HEADERI18NTABLE = HEADER_I18NTABLE,

    RPMTAG_SIGSIZE = RPMTAG_SIG_BASE,
    RPMTAG_SIGLEMD5_1 = RPMTAG_SIG_BASE + 2,
    RPMTAG_SIGPGP = RPMTAG_SIG_BASE + 3,
    RPMTAG_SIGLEMD5_2 = RPMTAG_SIG_BASE + 4,
    RPMTAG_SIGMD5 = RPMTAG_SIG_BASE + 5,

    RPMTAG_SIGGPG = RPMTAG_SIG_BASE + 6,
    RPMTAG_SIGPGP5 = RPMTAG_SIG_BASE + 7,

    RPMTAG_BADSHA1_1 = RPMTAG_SIG_BASE + 8,
    RPMTAG_BADSHA1_2 = RPMTAG_SIG_BASE + 9,
    RPMTAG_PUBKEYS = RPMTAG_SIG_BASE + 10,
    RPMTAG_DSAHEADER = RPMTAG_SIG_BASE + 11,
    RPMTAG_RSAHEADER = RPMTAG_SIG_BASE + 12,
    RPMTAG_SHA1HEADER = RPMTAG_SIG_BASE + 13,

    RPMTAG_LONGSIGSIZE = RPMTAG_SIG_BASE + 14,
    RPMTAG_LONGARCHIVESIZE = RPMTAG_SIG_BASE + 15,

    RPMTAG_SHA256HEADER = RPMTAG_SIG_BASE + 17,

    RPMTAG_NAME = 1000,

    RPMTAG_VERSION = 1001,

    RPMTAG_RELEASE = 1002,

    RPMTAG_EPOCH = 1003,

    RPMTAG_SUMMARY = 1004,
    RPMTAG_DESCRIPTION = 1005,
    RPMTAG_BUILDTIME = 1006,
    RPMTAG_BUILDHOST = 1007,
    RPMTAG_INSTALLTIME = 1008,
    RPMTAG_SIZE = 1009,
    RPMTAG_DISTRIBUTION = 1010,
    RPMTAG_VENDOR = 1011,
    RPMTAG_GIF = 1012,
    RPMTAG_XPM = 1013,
    RPMTAG_LICENSE = 1014,
    RPMTAG_PACKAGER = 1015,
    RPMTAG_GROUP = 1016,
    RPMTAG_CHANGELOG = 1017,
    RPMTAG_SOURCE = 1018,
    RPMTAG_PATCH = 1019,
    RPMTAG_URL = 1020,
    RPMTAG_OS = 1021,
    RPMTAG_ARCH = 1022,
    RPMTAG_PREIN = 1023,
    RPMTAG_POSTIN = 1024,
    RPMTAG_PREUN = 1025,
    RPMTAG_POSTUN = 1026,
    RPMTAG_OLDFILENAMES = 1027,
    RPMTAG_FILESIZES = 1028,
    RPMTAG_FILESTATES = 1029,
    RPMTAG_FILEMODES = 1030,
    RPMTAG_FILEUIDS = 1031,
    RPMTAG_FILEGIDS = 1032,
    RPMTAG_FILERDEVS = 1033,
    RPMTAG_FILEMTIMES = 1034,
    RPMTAG_FILEDIGESTS = 1035,

    RPMTAG_FILELINKTOS = 1036,
    RPMTAG_FILEFLAGS = 1037,
    RPMTAG_ROOT = 1038,
    RPMTAG_FILEUSERNAME = 1039,
    RPMTAG_FILEGROUPNAME = 1040,
    RPMTAG_EXCLUDE = 1041,
    RPMTAG_EXCLUSIVE = 1042,
    RPMTAG_ICON = 1043,
    RPMTAG_SOURCERPM = 1044,
    RPMTAG_FILEVERIFYFLAGS = 1045,
    RPMTAG_ARCHIVESIZE = 1046,
    RPMTAG_PROVIDENAME = 1047,

    RPMTAG_REQUIREFLAGS = 1048,
    RPMTAG_REQUIRENAME = 1049,

    RPMTAG_REQUIREVERSION = 1050,
    RPMTAG_NOSOURCE = 1051,
    RPMTAG_NOPATCH = 1052,
    RPMTAG_CONFLICTFLAGS = 1053,
    RPMTAG_CONFLICTNAME = 1054,

    RPMTAG_CONFLICTVERSION = 1055,
    RPMTAG_DEFAULTPREFIX = 1056,
    RPMTAG_BUILDROOT = 1057,
    RPMTAG_INSTALLPREFIX = 1058,
    RPMTAG_EXCLUDEARCH = 1059,
    RPMTAG_EXCLUDEOS = 1060,
    RPMTAG_EXCLUSIVEARCH = 1061,
    RPMTAG_EXCLUSIVEOS = 1062,
    RPMTAG_AUTOREQPROV = 1063,
    RPMTAG_RPMVERSION = 1064,
    RPMTAG_TRIGGERSCRIPTS = 1065,
    RPMTAG_TRIGGERNAME = 1066,
    RPMTAG_TRIGGERVERSION = 1067,
    RPMTAG_TRIGGERFLAGS = 1068,
    RPMTAG_TRIGGERINDEX = 1069,
    RPMTAG_VERIFYSCRIPT = 1079,
    RPMTAG_CHANGELOGTIME = 1080,
    RPMTAG_CHANGELOGNAME = 1081,
    RPMTAG_CHANGELOGTEXT = 1082,
    RPMTAG_BROKENMD5 = 1083,
    RPMTAG_PREREQ = 1084,
    RPMTAG_PREINPROG = 1085,
    RPMTAG_POSTINPROG = 1086,
    RPMTAG_PREUNPROG = 1087,
    RPMTAG_POSTUNPROG = 1088,
    RPMTAG_BUILDARCHS = 1089,
    RPMTAG_OBSOLETENAME = 1090,

    RPMTAG_VERIFYSCRIPTPROG = 1091,
    RPMTAG_TRIGGERSCRIPTPROG = 1092,
    RPMTAG_DOCDIR = 1093,
    RPMTAG_COOKIE = 1094,
    RPMTAG_FILEDEVICES = 1095,
    RPMTAG_FILEINODES = 1096,
    RPMTAG_FILELANGS = 1097,
    RPMTAG_PREFIXES = 1098,
    RPMTAG_INSTPREFIXES = 1099,
    RPMTAG_TRIGGERIN = 1100,
    RPMTAG_TRIGGERUN = 1101,
    RPMTAG_TRIGGERPOSTUN = 1102,
    RPMTAG_AUTOREQ = 1103,
    RPMTAG_AUTOPROV = 1104,
    RPMTAG_CAPABILITY = 1105,
    RPMTAG_SOURCEPACKAGE = 1106,
    RPMTAG_OLDORIGFILENAMES = 1107,
    RPMTAG_BUILDPREREQ = 1108,
    RPMTAG_BUILDREQUIRES = 1109,
    RPMTAG_BUILDCONFLICTS = 1110,
    RPMTAG_BUILDMACROS = 1111,
    RPMTAG_PROVIDEFLAGS = 1112,
    RPMTAG_PROVIDEVERSION = 1113,
    RPMTAG_OBSOLETEFLAGS = 1114,
    RPMTAG_OBSOLETEVERSION = 1115,
    RPMTAG_DIRINDEXES = 1116,
    RPMTAG_BASENAMES = 1117,
    RPMTAG_DIRNAMES = 1118,
    RPMTAG_ORIGDIRINDEXES = 1119,
    RPMTAG_ORIGBASENAMES = 1120,
    RPMTAG_ORIGDIRNAMES = 1121,
    RPMTAG_OPTFLAGS = 1122,
    RPMTAG_DISTURL = 1123,
    RPMTAG_PAYLOADFORMAT = 1124,
    RPMTAG_PAYLOADCOMPRESSOR = 1125,
    RPMTAG_PAYLOADFLAGS = 1126,
    RPMTAG_INSTALLCOLOR = 1127,
    RPMTAG_INSTALLTID = 1128,
    RPMTAG_REMOVETID = 1129,
    RPMTAG_SHA1RHN = 1130,
    RPMTAG_RHNPLATFORM = 1131,
    RPMTAG_PLATFORM = 1132,
    RPMTAG_PATCHESNAME = 1133,
    RPMTAG_PATCHESFLAGS = 1134,
    RPMTAG_PATCHESVERSION = 1135,
    RPMTAG_CACHECTIME = 1136,
    RPMTAG_CACHEPKGPATH = 1137,
    RPMTAG_CACHEPKGSIZE = 1138,
    RPMTAG_CACHEPKGMTIME = 1139,
    RPMTAG_FILECOLORS = 1140,
    RPMTAG_FILECLASS = 1141,
    RPMTAG_CLASSDICT = 1142,
    RPMTAG_FILEDEPENDSX = 1143,
    RPMTAG_FILEDEPENDSN = 1144,
    RPMTAG_DEPENDSDICT = 1145,
    RPMTAG_SOURCEPKGID = 1146,
    RPMTAG_FILECONTEXTS = 1147,
    RPMTAG_FSCONTEXTS = 1148,
    RPMTAG_RECONTEXTS = 1149,
    RPMTAG_POLICIES = 1150,
    RPMTAG_PRETRANS = 1151,
    RPMTAG_POSTTRANS = 1152,
    RPMTAG_PRETRANSPROG = 1153,
    RPMTAG_POSTTRANSPROG = 1154,
    RPMTAG_DISTTAG = 1155,
    RPMTAG_OLDSUGGESTSNAME = 1156,

    RPMTAG_OLDSUGGESTSVERSION = 1157,
    RPMTAG_OLDSUGGESTSFLAGS = 1158,
    RPMTAG_OLDENHANCESNAME = 1159,

    RPMTAG_OLDENHANCESVERSION = 1160,
    RPMTAG_OLDENHANCESFLAGS = 1161,
    RPMTAG_PRIORITY = 1162,
    RPMTAG_CVSID = 1163,

    RPMTAG_BLINKPKGID = 1164,
    RPMTAG_BLINKHDRID = 1165,
    RPMTAG_BLINKNEVRA = 1166,
    RPMTAG_FLINKPKGID = 1167,
    RPMTAG_FLINKHDRID = 1168,
    RPMTAG_FLINKNEVRA = 1169,
    RPMTAG_PACKAGEORIGIN = 1170,
    RPMTAG_TRIGGERPREIN = 1171,
    RPMTAG_BUILDSUGGESTS = 1172,
    RPMTAG_BUILDENHANCES = 1173,
    RPMTAG_SCRIPTSTATES = 1174,
    RPMTAG_SCRIPTMETRICS = 1175,
    RPMTAG_BUILDCPUCLOCK = 1176,
    RPMTAG_FILEDIGESTALGOS = 1177,
    RPMTAG_VARIANTS = 1178,
    RPMTAG_XMAJOR = 1179,
    RPMTAG_XMINOR = 1180,
    RPMTAG_REPOTAG = 1181,
    RPMTAG_KEYWORDS = 1182,
    RPMTAG_BUILDPLATFORMS = 1183,
    RPMTAG_PACKAGECOLOR = 1184,
    RPMTAG_PACKAGEPREFCOLOR = 1185,
    RPMTAG_XATTRSDICT = 1186,
    RPMTAG_FILEXATTRSX = 1187,
    RPMTAG_DEPATTRSDICT = 1188,
    RPMTAG_CONFLICTATTRSX = 1189,
    RPMTAG_OBSOLETEATTRSX = 1190,
    RPMTAG_PROVIDEATTRSX = 1191,
    RPMTAG_REQUIREATTRSX = 1192,
    RPMTAG_BUILDPROVIDES = 1193,
    RPMTAG_BUILDOBSOLETES = 1194,
    RPMTAG_DBINSTANCE = 1195,
    RPMTAG_NVRA = 1196,

    RPMTAG_FILENAMES = 5000,
    RPMTAG_FILEPROVIDE = 5001,
    RPMTAG_FILEREQUIRE = 5002,
    RPMTAG_FSNAMES = 5003,
    RPMTAG_FSSIZES = 5004,
    RPMTAG_TRIGGERCONDS = 5005,
    RPMTAG_TRIGGERTYPE = 5006,
    RPMTAG_ORIGFILENAMES = 5007,
    RPMTAG_LONGFILESIZES = 5008,
    RPMTAG_LONGSIZE = 5009,
    RPMTAG_FILECAPS = 5010,
    RPMTAG_FILEDIGESTALGO = 5011,
    RPMTAG_BUGURL = 5012,
    RPMTAG_EVR = 5013,
    RPMTAG_NVR = 5014,
    RPMTAG_NEVR = 5015,
    RPMTAG_NEVRA = 5016,
    RPMTAG_HEADERCOLOR = 5017,
    RPMTAG_VERBOSE = 5018,
    RPMTAG_EPOCHNUM = 5019,
    RPMTAG_PREINFLAGS = 5020,
    RPMTAG_POSTINFLAGS = 5021,
    RPMTAG_PREUNFLAGS = 5022,
    RPMTAG_POSTUNFLAGS = 5023,
    RPMTAG_PRETRANSFLAGS = 5024,
    RPMTAG_POSTTRANSFLAGS = 5025,
    RPMTAG_VERIFYSCRIPTFLAGS = 5026,
    RPMTAG_TRIGGERSCRIPTFLAGS = 5027,
    RPMTAG_COLLECTIONS = 5029,
    RPMTAG_POLICYNAMES = 5030,
    RPMTAG_POLICYTYPES = 5031,
    RPMTAG_POLICYTYPESINDEXES = 5032,
    RPMTAG_POLICYFLAGS = 5033,
    RPMTAG_VCS = 5034,
    RPMTAG_ORDERNAME = 5035,
    RPMTAG_ORDERVERSION = 5036,
    RPMTAG_ORDERFLAGS = 5037,
    RPMTAG_MSSFMANIFEST = 5038,
    RPMTAG_MSSFDOMAIN = 5039,
    RPMTAG_INSTFILENAMES = 5040,
    RPMTAG_REQUIRENEVRS = 5041,
    RPMTAG_PROVIDENEVRS = 5042,
    RPMTAG_OBSOLETENEVRS = 5043,
    RPMTAG_CONFLICTNEVRS = 5044,
    RPMTAG_FILENLINKS = 5045,
    RPMTAG_RECOMMENDNAME = 5046,

    RPMTAG_RECOMMENDVERSION = 5047,
    RPMTAG_RECOMMENDFLAGS = 5048,
    RPMTAG_SUGGESTNAME = 5049,

    RPMTAG_SUGGESTVERSION = 5050,
    RPMTAG_SUGGESTFLAGS = 5051,
    RPMTAG_SUPPLEMENTNAME = 5052,

    RPMTAG_SUPPLEMENTVERSION = 5053,
    RPMTAG_SUPPLEMENTFLAGS = 5054,
    RPMTAG_ENHANCENAME = 5055,

    RPMTAG_ENHANCEVERSION = 5056,
    RPMTAG_ENHANCEFLAGS = 5057,
    RPMTAG_RECOMMENDNEVRS = 5058,
    RPMTAG_SUGGESTNEVRS = 5059,
    RPMTAG_SUPPLEMENTNEVRS = 5060,
    RPMTAG_ENHANCENEVRS = 5061,
    RPMTAG_ENCODING = 5062,
    RPMTAG_FILETRIGGERIN = 5063,
    RPMTAG_FILETRIGGERUN = 5064,
    RPMTAG_FILETRIGGERPOSTUN = 5065,
    RPMTAG_FILETRIGGERSCRIPTS = 5066,
    RPMTAG_FILETRIGGERSCRIPTPROG = 5067,
    RPMTAG_FILETRIGGERSCRIPTFLAGS = 5068,
    RPMTAG_FILETRIGGERNAME = 5069,
    RPMTAG_FILETRIGGERINDEX = 5070,
    RPMTAG_FILETRIGGERVERSION = 5071,
    RPMTAG_FILETRIGGERFLAGS = 5072,
    RPMTAG_TRANSFILETRIGGERIN = 5073,
    RPMTAG_TRANSFILETRIGGERUN = 5074,
    RPMTAG_TRANSFILETRIGGERPOSTUN = 5075,
    RPMTAG_TRANSFILETRIGGERSCRIPTS = 5076,
    RPMTAG_TRANSFILETRIGGERSCRIPTPROG = 5077,
    RPMTAG_TRANSFILETRIGGERSCRIPTFLAGS = 5078,
    RPMTAG_TRANSFILETRIGGERNAME = 5079,
    RPMTAG_TRANSFILETRIGGERINDEX = 5080,
    RPMTAG_TRANSFILETRIGGERVERSION = 5081,
    RPMTAG_TRANSFILETRIGGERFLAGS = 5082,
    RPMTAG_REMOVEPATHPOSTFIXES = 5083,
    RPMTAG_FILETRIGGERPRIORITIES = 5084,
    RPMTAG_TRANSFILETRIGGERPRIORITIES = 5085,
    RPMTAG_FILETRIGGERCONDS = 5086,
    RPMTAG_FILETRIGGERTYPE = 5087,
    RPMTAG_TRANSFILETRIGGERCONDS = 5088,
    RPMTAG_TRANSFILETRIGGERTYPE = 5089,
    RPMTAG_FILESIGNATURES = 5090,
    RPMTAG_FILESIGNATURELENGTH = 5091,
    RPMTAG_PAYLOADDIGEST = 5092,
    RPMTAG_PAYLOADDIGESTALGO = 5093,
    RPMTAG_AUTOINSTALLED = 5094,
    RPMTAG_IDENTITY = 5095,
    RPMTAG_MODULARITYLABEL = 5096,
}

#[derive(
    num_derive::FromPrimitive,
    num_derive::ToPrimitive,
    Debug,
    PartialEq,
    enum_display_derive::Display,
)]
enum IndexSignatureTag {
    HEADER_SIGNATURES = HEADER_SIGNATURES,
    // This tag specifies the combined size of the Header and Payload sections.
    RPMSIGTAG_SIZE = HEADER_TAGBASE,

    //This  tag  specifies  the  uncompressed  size of the Payload archive, including the cpio headers.
    RPMSIGTAG_PAYLOADSIZE = HEADER_TAGBASE + 7,

    //This  index  contains  the  SHA1  checksum  of  the  entire  Header  Section,
    //including the Header Record, Index Records and Header store.
    RPMSIGTAG_SHA1 = 269,

    //This  tag  specifies  the  128-bit  MD5  checksum  of  the  combined  Header  and  Archive sections.
    RPMSIGTAG_MD5 = 1004,

    //The  tag  contains  the  DSA  signature  of  the  Header  section.
    // The  data  is  formatted  as  a  Version  3  Signature  Packet  as  specified  in  RFC  2440:  OpenPGP Message Format.
    // If this tag is present, then the SIGTAG_GPG tag shall also be present.
    RPMSIGTAG_DSA = 267,

    // The  tag  contains  the  RSA  signature  of  the  Header  section.
    // The  data  is  formatted  as  a  Version  3  Signature  Packet  as  specified  in  RFC  2440: OpenPGP  Message  Format.
    // If  this  tag  is  present,  then  the  SIGTAG_PGP  shall also be present.
    RPMSIGTAG_RSA = 268,

    // This  tag  specifies  the  RSA  signature  of  the  combined  Header  and  Payload  sections.
    // The data is formatted as a Version 3 Signature Packet as specified in RFC 2440: OpenPGP Message Format.
    RPMSIGTAG_PGP = 1002,

    // The  tag  contains  the  DSA  signature  of  the  combined  Header  and  Payload  sections.
    // The data is formatted as a Version 3 Signature Packet as specified in RFC 2440: OpenPGP Message Format.
    RPMSIGTAG_GPG = 1005,
}

fn parse_entry_data_number<'a, T, E, F>(
    mut input: &'a [u8],
    num_items: u32,
    items: &mut Vec<T>,
    parser: F,
) -> nom::IResult<&'a [u8], (), E>
where
    E: nom::error::ParseError<&'a [u8]>,
    F: Fn(&'a [u8]) -> nom::IResult<&'a [u8], T, E>,
{
    for _ in 0..num_items {
        let (rest, data) = parser(input)?;
        items.push(data);
        input = rest;
    }

    Ok((input, ()))
}

struct RPMError {
    message: String,
}

impl std::error::Error for RPMError {}

impl RPMError {
    fn new(message: &str) -> Self {
        RPMError {
            message: message.to_string(),
        }
    }
}

impl fmt::Display for RPMError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message) // user-facing output
    }
}

// Implement std::fmt::Debug for AppError
impl fmt::Debug for RPMError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message) // programmer-facing output
    }
}

impl From<io::Error> for RPMError {
    fn from(error: io::Error) -> Self {
        RPMError {
            message: error.to_string(),
        }
    }
}

impl From<nom::Err<(&[u8], nom::error::ErrorKind)>> for RPMError {
    fn from(error: nom::Err<(&[u8], nom::error::ErrorKind)>) -> Self {
        match error {
            nom::Err::Error((_, kind)) | nom::Err::Failure((_, kind)) => {
                return RPMError {
                    message: kind.description().to_string(),
                }
            }
            nom::Err::Incomplete(_) => {
                return RPMError {
                    message: "unhandled incomplete".to_string(),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use std::io::prelude::*;

    #[test]
    fn test_header() -> Result<(), Box<std::error::Error>> {
        let mut d = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let mut rpm_file_path = d.clone();
        rpm_file_path.push("389-ds-base-devel-1.3.8.4-15.el7.x86_64.rpm");
        let mut rpm_file =
            std::fs::File::open(rpm_file_path).expect("should be able to open rpm file");
        let mut buf_reader = std::io::BufReader::new(rpm_file);

        let package = RPMPackage::parse(&mut buf_reader)?;
        let metadata = &package.metadata;
        assert_eq!(7, metadata.signature.index_entries.len());
        assert!(metadata.signature.index_entries[0].num_items == 16);
        assert_eq!(1156, metadata.signature.index_header.header_size);

        let expected_data = vec![
            (
                16,
                IndexData::Bin(vec![
                    0x00, 0x00, 0x00, 0x3e, 0x00, 0x00, 0x00, 0x07, 0xff, 0xff, 0xff, 0x90, 0x00,
                    0x00, 0x00, 0x10,
                ]),
                IndexSignatureTag::HEADER_SIGNATURES,
            ),
            (
                536,
                IndexData::Bin(vec![
                    0x89, 0x02, 0x15, 0x03, 0x05, 0x00, 0x5b, 0xe9, 0x8c, 0x5b, 0x24, 0xc6, 0xa8,
                    0xa7, 0xf4, 0xa8, 0x0e, 0xb5, 0x01, 0x08, 0xa8, 0x4c, 0x0f, 0xfd, 0x1a, 0x9d,
                    0xe3, 0x0f, 0x7e, 0xbb, 0x74, 0xe3, 0x62, 0xef, 0xfd, 0x4d, 0x1c, 0x11, 0xa1,
                    0x68, 0x22, 0x0d, 0xff, 0x4a, 0x72, 0x11, 0x18, 0xe4, 0xb0, 0x46, 0x6b, 0x11,
                    0x82, 0xc6, 0xd4, 0xd6, 0xdb, 0x53, 0x64, 0x1b, 0x32, 0x33, 0x41, 0x95, 0xf3,
                    0x0c, 0xa6, 0xc2, 0x50, 0xee, 0x81, 0x81, 0x6a, 0x08, 0x05, 0xfa, 0x3b, 0x26,
                    0x66, 0x63, 0x5c, 0xfa, 0x4b, 0x25, 0x02, 0xe7, 0xad, 0x3f, 0x4f, 0x82, 0x7a,
                    0xa3, 0x4d, 0xad, 0x0d, 0xa0, 0x19, 0x63, 0x77, 0xd2, 0x18, 0x30, 0x54, 0xc7,
                    0x14, 0x23, 0x22, 0x0b, 0x0d, 0xd8, 0xba, 0x1b, 0x6c, 0x94, 0xb3, 0x0f, 0xb3,
                    0x82, 0x18, 0x62, 0x33, 0x51, 0x4e, 0xaa, 0xfa, 0x84, 0x8a, 0x4b, 0xcd, 0x82,
                    0x72, 0xf1, 0x40, 0x94, 0x38, 0xc7, 0xbc, 0x48, 0x29, 0x4f, 0x32, 0x98, 0xd9,
                    0xaf, 0x35, 0x1a, 0x0b, 0xf0, 0x87, 0x74, 0x39, 0xd6, 0xe7, 0x86, 0x44, 0x9d,
                    0x5c, 0x7a, 0xde, 0x63, 0x1a, 0x16, 0xb2, 0x29, 0x1d, 0x46, 0x9e, 0x61, 0xad,
                    0xff, 0x91, 0x6f, 0x51, 0x65, 0x8a, 0xb9, 0x37, 0x0e, 0x65, 0xb6, 0x77, 0x2f,
                    0xb7, 0x74, 0x6a, 0x9c, 0x8a, 0xf0, 0x4b, 0x2d, 0x87, 0xbf, 0x61, 0xff, 0x70,
                    0xdc, 0x29, 0xec, 0x9a, 0x0c, 0x7f, 0x12, 0xf6, 0x55, 0xea, 0x22, 0xb5, 0xf0,
                    0x1a, 0x0d, 0xa5, 0xe8, 0xc6, 0x7f, 0x1b, 0x9c, 0x55, 0x1b, 0x35, 0x5c, 0xac,
                    0x72, 0x26, 0x86, 0x89, 0x30, 0xd5, 0x2d, 0x08, 0x93, 0x0f, 0x9e, 0x1a, 0xfd,
                    0x8c, 0x7e, 0xdb, 0xca, 0x57, 0x4f, 0xd9, 0x42, 0xd7, 0xf6, 0x74, 0xcd, 0xf6,
                    0x68, 0xef, 0xe3, 0x24, 0x66, 0x92, 0x29, 0xda, 0x96, 0x87, 0x8e, 0xa2, 0x88,
                    0x23, 0x78, 0xee, 0xc3, 0xfc, 0x71, 0xfd, 0xb6, 0x36, 0x6b, 0xad, 0xd7, 0x54,
                    0x55, 0x4d, 0xa0, 0xa3, 0x40, 0x70, 0x51, 0xc2, 0x76, 0xde, 0x9f, 0xa3, 0xe5,
                    0x7f, 0x80, 0x72, 0xa9, 0xc3, 0x7f, 0x3e, 0x37, 0xd7, 0x7a, 0x99, 0x98, 0xc4,
                    0xc6, 0x4b, 0x51, 0x93, 0xbc, 0xd0, 0xf2, 0x93, 0x09, 0x73, 0x7f, 0x6e, 0x7a,
                    0xb4, 0x6b, 0x7b, 0x79, 0xe0, 0x45, 0x55, 0x39, 0xfc, 0x61, 0xa7, 0xde, 0xa5,
                    0xff, 0x80, 0x31, 0x39, 0x14, 0xf6, 0xb6, 0x07, 0x6c, 0xd7, 0xa4, 0x10, 0xa0,
                    0x87, 0x55, 0x4d, 0xe5, 0xa5, 0x26, 0xc1, 0x99, 0x0e, 0x58, 0x19, 0xae, 0xc3,
                    0xbf, 0xe8, 0x16, 0x48, 0xe0, 0x85, 0x96, 0x51, 0x18, 0x72, 0xb8, 0x0f, 0x00,
                    0x9f, 0x26, 0xde, 0xec, 0x12, 0x32, 0xec, 0xd0, 0x3c, 0xde, 0x31, 0x0b, 0xd6,
                    0xbf, 0x4a, 0xc5, 0x66, 0x5c, 0xcd, 0xb0, 0x29, 0x3c, 0x6d, 0xc6, 0x18, 0x56,
                    0xd7, 0x17, 0xb4, 0x4d, 0xeb, 0xdc, 0xbb, 0xe4, 0x4f, 0x1a, 0xf5, 0x72, 0x3a,
                    0x96, 0x44, 0x4d, 0xf3, 0x14, 0xb1, 0x79, 0x75, 0xa4, 0x6a, 0xcc, 0x9d, 0x27,
                    0x47, 0xa9, 0x12, 0xa7, 0x07, 0xa8, 0x30, 0xae, 0xf2, 0xde, 0xbc, 0x33, 0x87,
                    0xb5, 0x8c, 0x05, 0x3f, 0x45, 0x4e, 0x64, 0x4a, 0x86, 0x6d, 0xc3, 0xf4, 0xfe,
                    0x05, 0x91, 0x81, 0x95, 0x2f, 0xad, 0x81, 0xda, 0x1b, 0x39, 0xf8, 0xf0, 0xb8,
                    0x46, 0xf0, 0x38, 0x82, 0xa6, 0xf2, 0x35, 0x34, 0x4d, 0x9e, 0x17, 0x9a, 0x97,
                    0xaf, 0xbd, 0x9b, 0x19, 0x31, 0x88, 0xd8, 0x3a, 0x50, 0x2e, 0x91, 0x50, 0x45,
                    0x05, 0x92, 0x88, 0xb2, 0x07, 0x10, 0x9a, 0x6c, 0x44, 0xa2, 0x72, 0x0f, 0xca,
                    0x68, 0x17, 0x99, 0x1a, 0x62, 0xcd, 0x66, 0x23, 0x0f, 0x90, 0xa4, 0x14, 0xa6,
                    0x6c, 0x7d, 0x06, 0xc4, 0x4b, 0xbe, 0x81, 0x47, 0x72, 0xeb, 0xd4, 0xa2, 0x3d,
                    0x63, 0x73, 0x86, 0xef, 0x0e, 0x2b, 0x78, 0xd4, 0x4f, 0x48, 0x2e, 0xb0, 0x55,
                    0x8c, 0x8e, 0x5d,
                ]),
                IndexSignatureTag::RPMSIGTAG_RSA,
            ),
            (
                1,
                IndexData::StringTag("6178620331c1fe63c5dd3da7c118058e366e37d8".to_string()),
                IndexSignatureTag::RPMSIGTAG_SHA1,
            ),
            (
                1,
                IndexData::Int32(vec![275904]),
                IndexSignatureTag::RPMSIGTAG_SIZE,
            ),
            (
                536,
                IndexData::Bin(vec![
                    0x89, 0x02, 0x15, 0x03, 0x05, 0x00, 0x5b, 0xe9, 0x8c, 0x5b, 0x24, 0xc6, 0xa8,
                    0xa7, 0xf4, 0xa8, 0x0e, 0xb5, 0x01, 0x08, 0x54, 0xe7, 0x10, 0x00, 0xc4, 0xbb,
                    0xc5, 0x5b, 0xe7, 0xe3, 0x80, 0xbd, 0xe9, 0x0a, 0xc6, 0x32, 0x6a, 0x42, 0x4a,
                    0xb0, 0xa9, 0xf5, 0x95, 0xf1, 0xa9, 0x31, 0x4a, 0x22, 0xfc, 0xf8, 0xdc, 0xcf,
                    0x89, 0xd8, 0x30, 0x19, 0x83, 0x55, 0xf0, 0xb5, 0xa1, 0x0c, 0xd3, 0x6b, 0x69,
                    0x21, 0x8f, 0x05, 0xe5, 0x17, 0x5c, 0x29, 0x99, 0x84, 0x84, 0xc6, 0xf2, 0xa7,
                    0xcf, 0xe9, 0xd4, 0x99, 0x42, 0x20, 0x39, 0xf5, 0xd9, 0x96, 0x6a, 0xc3, 0x01,
                    0x13, 0xfa, 0x46, 0xee, 0x6d, 0xcb, 0x01, 0xf7, 0xc9, 0x34, 0x26, 0x8e, 0x9e,
                    0xba, 0x5d, 0x89, 0xb9, 0xd9, 0x21, 0x15, 0x06, 0x51, 0xa6, 0xad, 0x70, 0xc5,
                    0x3a, 0xd8, 0xa8, 0x84, 0x94, 0xbe, 0x29, 0xc1, 0x9b, 0x53, 0x38, 0x26, 0x90,
                    0x8b, 0x7d, 0xd2, 0xa0, 0x7c, 0xcc, 0xa2, 0x77, 0x60, 0xfa, 0xb9, 0x7f, 0x90,
                    0x77, 0xc7, 0xb9, 0xad, 0x7e, 0xab, 0xa0, 0xdb, 0xa3, 0x29, 0xec, 0x72, 0xa0,
                    0x70, 0xd1, 0xed, 0x9a, 0x8c, 0x30, 0x6b, 0xdf, 0xc5, 0x8b, 0x0f, 0xc8, 0x14,
                    0xca, 0xe1, 0x2b, 0x95, 0x14, 0x6a, 0x70, 0x21, 0x23, 0x49, 0x14, 0x70, 0xe6,
                    0x84, 0xe1, 0xf1, 0xd0, 0x6f, 0xc0, 0x7d, 0xcd, 0xb7, 0xdf, 0xd4, 0xc6, 0xd3,
                    0xd0, 0x17, 0x5d, 0xb3, 0xf4, 0xaf, 0xd3, 0xea, 0xaa, 0xed, 0x2f, 0x72, 0x02,
                    0xfb, 0xd4, 0x46, 0x75, 0x2a, 0xc3, 0x38, 0x50, 0xd7, 0xb2, 0x5b, 0x61, 0x64,
                    0x25, 0x07, 0x8c, 0x9b, 0x01, 0xf8, 0x6f, 0xeb, 0xbb, 0x5d, 0xb0, 0x02, 0x81,
                    0x30, 0xeb, 0x4b, 0x01, 0xe1, 0xff, 0x9f, 0x24, 0xa7, 0xe3, 0xde, 0x71, 0x51,
                    0x96, 0x92, 0xd0, 0x60, 0x18, 0xc3, 0x60, 0xd5, 0xae, 0xd7, 0x40, 0x26, 0x57,
                    0xf3, 0xdb, 0x6a, 0x81, 0x97, 0x64, 0x10, 0x24, 0x05, 0x7d, 0x54, 0x95, 0x8d,
                    0x36, 0x5f, 0x23, 0xd7, 0x17, 0x1a, 0x83, 0xca, 0xf0, 0xe6, 0x1d, 0x27, 0x22,
                    0xdc, 0xb6, 0x04, 0x0d, 0xe8, 0x25, 0xe6, 0xc4, 0xe0, 0x26, 0x17, 0x42, 0x03,
                    0x36, 0xfe, 0xf8, 0xc7, 0xc2, 0xdb, 0xa2, 0xb7, 0x99, 0x3a, 0xec, 0xe2, 0xd4,
                    0x93, 0x3d, 0x53, 0x0d, 0x26, 0x96, 0x84, 0x6e, 0x4b, 0xfa, 0xb3, 0xca, 0x98,
                    0x8a, 0x65, 0xa8, 0x62, 0x7d, 0xbf, 0x1f, 0x80, 0xbf, 0xa3, 0xa6, 0xe7, 0x03,
                    0x0e, 0x15, 0xb7, 0x73, 0x37, 0xdb, 0x35, 0x35, 0x6f, 0xce, 0x71, 0xd0, 0x3c,
                    0x15, 0x76, 0x6d, 0x26, 0xe5, 0xf6, 0xae, 0x50, 0xc8, 0x28, 0xa5, 0xb3, 0xdf,
                    0xd3, 0x24, 0xb9, 0x3f, 0xfd, 0xcc, 0x02, 0x60, 0xe4, 0xfd, 0x10, 0x71, 0x0a,
                    0xbe, 0xdf, 0x19, 0x23, 0xa1, 0x71, 0xe6, 0x99, 0x3c, 0xef, 0xd5, 0x41, 0x20,
                    0x7a, 0x9a, 0x8c, 0x24, 0xe8, 0x74, 0x83, 0xdd, 0xab, 0xea, 0x87, 0x38, 0xca,
                    0x8e, 0x3d, 0x60, 0x14, 0x20, 0xc7, 0x02, 0xed, 0xa1, 0xdc, 0xd5, 0xcf, 0x22,
                    0x14, 0x14, 0x93, 0x9c, 0x68, 0x95, 0xbf, 0x6e, 0xdd, 0x28, 0x3e, 0xfc, 0xa0,
                    0xfb, 0x37, 0xdf, 0x9c, 0x7c, 0xef, 0x37, 0x11, 0x7a, 0xa3, 0x28, 0x71, 0xd5,
                    0xca, 0xa3, 0x17, 0x09, 0xa9, 0x92, 0xc9, 0x1a, 0x2b, 0x5d, 0xac, 0x0e, 0xee,
                    0x10, 0xc4, 0x97, 0xad, 0x18, 0x4e, 0x1a, 0xb7, 0x2a, 0xd2, 0x1c, 0xb6, 0x9d,
                    0x8b, 0x22, 0x91, 0x61, 0x9f, 0x6e, 0xe0, 0x06, 0x9c, 0xc2, 0x21, 0x8f, 0x24,
                    0x95, 0x80, 0x19, 0x17, 0x15, 0x5c, 0xba, 0x27, 0x9f, 0xa4, 0xc8, 0x19, 0xd1,
                    0xfb, 0x64, 0xf7, 0x36, 0x5e, 0x6b, 0x36, 0xba, 0x25, 0x27, 0x3d, 0x31, 0x74,
                    0x9e, 0x53, 0xf7, 0x23, 0xe2, 0x00, 0x0c, 0x86, 0x9c, 0xab, 0x3f, 0xf5, 0x44,
                    0x6e, 0xaa, 0xd8, 0x03, 0x8b, 0x2e, 0x8c, 0xca, 0x14, 0xfe, 0x1d, 0xad, 0x6b,
                    0x5e, 0x60, 0x8d,
                ]),
                IndexSignatureTag::RPMSIGTAG_PGP,
            ),
            (
                16,
                IndexData::Bin(vec![
                    0xdb, 0x6d, 0xf4, 0x9b, 0x40, 0x19, 0x6e, 0x84, 0x5e, 0xed, 0x42, 0xe2, 0x16,
                    0x62, 0x28, 0x67,
                ]),
                IndexSignatureTag::RPMSIGTAG_MD5,
            ),
            (
                1,
                IndexData::Int32(vec![510164]),
                IndexSignatureTag::RPMSIGTAG_PAYLOADSIZE,
            ),
        ];

        for (i, (len, data, tag)) in expected_data.iter().enumerate() {
            assert_eq!(*len as u32, metadata.signature.index_entries[i].num_items);
            assert_eq!(data, &metadata.signature.index_entries[i].data);
            assert_eq!(*tag, metadata.signature.index_entries[i].tag);
        }

        assert_eq!("cpio", metadata.header.get_payload_format()?);
        assert_eq!("xz", metadata.header.get_payload_compressor()?);

        let expected_file_checksums = vec![
            "",
            "3e4e2501e2a70343a661b0b85b82e27b2090a7e595dc3b5c91e732244ffc3272",
            "d36ab638ed0635afcb1582387d676b2e461c5a88ac05a6e2aada8b40b4175bc1",
            "9667aa81021c9f4d48690ef6fbb3e7d623bdae94e2da414abd044dc38e52f037",
            "1e8235e08aac746155c209c1e641e73bf7a4c34d9971aaa9f864226bd5de9d99",
            "53a1e216749208c0bdfc9e8ec70f4bb9459ad1ff224571a7a432e472d2202986",
            "2807bb4e77579c81dc7e283d60612a6ecc3ce56000691cac744a4bca73cea241",
            "",
            "",
            "",
            "",
            "",
            "a839e2870b7a212ca9dc6f92007907bc42de1984eac6c278a519d4115071f322",
            "3ca364e71a110cd0f2317fbaf99bc8552b8374dbeaf0a989695990f940d88bea",
            "eead9f55f0774559d37b20fbc5448f978e1a80d27f488768cbbb278a932e7e9f",
            "",
            "495b7c1e22dcc0f37d78076a1fcad786b69ac78f1e806466d798fd8fc4a5d10d",
            "8ceb4b9ee5adedde47b31e975c1d90c73ad27b6b165a1dcd80c7c545eb65b903",
            "a73b7d3598e98f46aeb0559e641d3e6ac83c0fc34e1e5fa98cb9d4a6050bacd9",
            "97a6a0413ce3664e192dff12a29bc3f690c24e8a0d48d986478c56cdfe370c3b",
            "d110052464fd35c5dc227b3f071606ec40c12ba773fec9ec88ad01430bd4a27b",
            "5c3adbdea58a8bb7663c65216dda7d1f38a17b067f718df46ece04ecb503f689",
            "005dc9d5aa85b10c3200535af8b0ed2123770e3a79d48be5067e81cc553d55bd",
            "aa7ea2def38dfc965b27ae20467006aca779e02ad366d50824c4615a7d43af27",
            "5ee25b47a83b1431f6ecb1d0a292a8e9a2917c1de9e87129c86cdda743be3f55",
            "413aae4fb264aad9d35db94eb28b5f70a7183101692943e81bc90d6718418d8e",
            "66004b2e338ce29e59d6a26467e251f092ae0a0f33b67dbba67d2ea9f3ec89f6",
            "3db4ad3317bff658a04a1bdbc01fab83cd348f76a1d44585b892fdb0223f2b77",
            "ccac76a229e6739ab318d9ede59f6b980d3200fc50669409d3b1e8a0ff1fa029",
            "5a3378c84c68e2a407add0f850c64d701af2aedcca67dd2489e86cb1e08dbb6b",
            "da188ece6801b97c98031b854d4000e348e969edea239cb1bcbfae7a194e3520",
            "28a93db2fe665e8b08494fe5adf3d8dc00c2f96a4994a09eb70cf982d912fa09",
            "ba92ea5c90389b38a3c003a5e4a7b09e57473cbd2fb3645c2c0012808023fd0b",
            "502dd15afe5609a113108cad047a810b7a97cc8819e830f1d5b00cb5bf65a295",
            "4445b3e6550a3d7da96a246e6138d3f349160420085ce14222d3f686eb29915c",
            "649f748bffe197539db9237d56da8a3e408731488550617596359cd32731ec06",
            "4bd801d053bf456c3dd2c94f9721d1bb0c44d2c119e233b8ad4c5189bd39b256",
            "d444bb47f4a83ebd0e6b669f73bb2d6d3dde804b70a0bbd2be66693d88ce8e16",
            "087be3693057db21a0b1d38844bb5efa8112f67f3572063546215f25f9fe8d9e",
            "2c639c8768e323f2ad4ea96f1667989cb97d49947e9bcebcd449163d9c9bb85c",
        ];

        let checksums = metadata.header.get_file_checksums()?;

        assert_eq!(expected_file_checksums, checksums);

        let mut buf = Vec::new();

        package.metadata.lead.write(&mut buf)?;
        assert_eq!(96, buf.len());

        let lead = Lead::parse(&buf)?;
        assert!(package.metadata.lead == lead);

        buf_reader.seek(io::SeekFrom::Start(0))?;
        let mut expected = vec![0; 96];
        // buf_reader.read_to_end(&mut expected);
        buf_reader.read_exact(&mut expected)?;

        for i in 0..expected.len() {
            assert_eq!(expected[i], buf[i]);
        }

        buf = Vec::new();
        package.metadata.signature.write_signature(&mut buf)?;
        let signature = Header::parse_signature(&mut buf.as_ref())?;
        assert_eq!(package.metadata.signature, signature);

        buf = Vec::new();
        package.metadata.header.write(&mut buf)?;
        let header = Header::parse(&mut buf.as_ref())?;
        assert_eq!(package.metadata.header, header);

        buf = Vec::new();
        package.write(&mut buf)?;
        let second_pkg = RPMPackage::parse(&mut buf.as_ref())?;
        assert_eq!(package.content.len(), second_pkg.content.len());
        assert!(package.metadata == second_pkg.metadata);

        Ok(())
    }
}
