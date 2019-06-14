use nom;

use cpio;
use enum_display_derive;

use md5;
use nom::bytes::complete;
use nom::number::complete::{be_i16, be_i32, be_i64, be_i8, be_u16, be_u32, be_u8};
use num;
use num_derive;
use sha1;
use sha2;
use sha2::Digest;
use std::os::unix::fs::PermissionsExt;
use std::collections:: BTreeMap;
use std::convert::TryInto;
use std::fmt;
use std::fmt::Display;
use std::io::{self,Write, Read};
use std::time::UNIX_EPOCH;


const LEAD_SIZE: usize = 96;
const RPM_MAGIC: [u8; 4] = [0xed, 0xab, 0xee, 0xdb];

const HEADER_MAGIC: [u8; 3] = [0x8e, 0xad, 0xe8];

pub struct RPMPackage {
    pub metadata: RPMPackageMetadata,
    pub content: Vec<u8>,
}

impl RPMPackage {
    pub fn parse<T: std::io::BufRead>(input: &mut T) -> Result<Self, RPMError> {
        let metadata = RPMPackageMetadata::parse(input)?;
        let mut content = Vec::new();
        input.read_to_end(&mut content)?;
        Ok(RPMPackage { metadata, content })
    }

    pub fn write<W: std::io::Write>(&self, out: &mut W) -> Result<(), RPMError> {
        self.metadata.write(out)?;
        out.write_all(&self.content)?;
        Ok(())
    }
}
#[derive(PartialEq)]
pub struct RPMPackageMetadata {
    pub lead: Lead,
    pub signature: Header<IndexSignatureTag>,
    pub header: Header<IndexTag>,
}

impl RPMPackageMetadata {
    fn parse<T: std::io::BufRead>(input: &mut T) -> Result<Self, RPMError> {
        let mut lead_buffer = [0; LEAD_SIZE];
        input.read_exact(&mut lead_buffer)?;
        let lead = Lead::parse(&lead_buffer)?;
        let signature_header = Header::parse_signature(input)?;
        let header = Header::parse(input)?;
        Ok(RPMPackageMetadata {
            lead,
            signature: signature_header,
            header,
        })
    }

    fn write<W: std::io::Write>(&self, out: &mut W) -> Result<(), RPMError> {
        self.lead.write(out)?;
        self.signature.write_signature(out)?;
        self.header.write(out)?;
        Ok(())
    }
}

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
    fn parse(input: &[u8]) -> Result<Self, RPMError> {
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

    fn new(name: &str) -> Self {
        let mut name_size = name.len();

        // the last byte needs to be the null terminator
        if name_size > 65 {
            name_size = 65;
        }

        let mut name_arr = [0; 66];
        name_arr[..name_size - 1].clone_from_slice(&name.as_bytes()[..name_size - 1]);
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

#[derive(Debug, PartialEq)]
pub struct Header<T: num::FromPrimitive> {
    index_header: IndexHeader,
    index_entries: Vec<IndexEntry<T>>,
    store: Vec<u8>,
}

impl<T> Header<T>
where
    T: num::FromPrimitive + num::ToPrimitive + PartialEq + Display + std::fmt::Debug + Copy,
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

        let store = Vec::from(bytes);
        // add data to entries
        for entry in &mut entries {
            let mut remaining = &bytes[entry.offset as usize..];
            match &mut entry.data {
                IndexData::Null => {}
                IndexData::Char(ref mut chars) => {
                    parse_entry_data_number(remaining, entry.num_items, chars, be_u8)?;
                }
                IndexData::Int8(ref mut ints) => {
                    parse_entry_data_number(remaining, entry.num_items, ints, be_i8)?;
                }
                IndexData::Int16(ref mut ints) => {
                    parse_entry_data_number(remaining, entry.num_items, ints, be_i16)?;
                }
                IndexData::Int32(ref mut ints) => {
                    parse_entry_data_number(remaining, entry.num_items, ints, be_i32)?;
                }
                IndexData::Int64(ref mut ints) => {
                    parse_entry_data_number(remaining, entry.num_items, ints, be_i64)?;
                }
                IndexData::StringTag(ref mut string) => {
                    let (_rest, raw_string) = complete::take_till(|item| item == 0)(remaining)?;
                    string.push_str(String::from_utf8_lossy(raw_string).as_ref());
                }
                IndexData::Bin(ref mut bin) => {
                    parse_entry_data_number(remaining, entry.num_items, bin, be_u8)?;
                }
                IndexData::StringArray(ref mut strings) => {
                    for _ in 0..entry.num_items {
                        let (rest, raw_string) = complete::take_till(|item| item == 0)(remaining)?;
                        // the null byte is still in there.. we need to cut it out.
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
            index_header,
            index_entries: entries,
            store,
        })
    }

    fn write<W: std::io::Write>(&self, out: &mut W) -> Result<(), RPMError> {
        self.index_header.write(out)?;
        for entry in &self.index_entries {
            entry.write_index(out)?;
        }
        out.write_all(&self.store)?;
        Ok(())
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
        entry.data.string().ok_or_else(|| {
            RPMError::new(&format!(
                "tag {} has datatype {}, not string",
                entry.tag, entry.data,
            ))
        })
    }

    fn get_entry_string_array_data(&self, tag: T) -> Result<&[String], RPMError> {
        let entry = self.find_entry_or_err(&tag)?;
        entry.data.string_array().ok_or_else(|| {
            RPMError::new(&format!("tag {} does not provide string array", entry.tag,))
        })
    }

    fn create_region_tag(tag: T, records_count: i32, offset: i32) -> IndexEntry<T> {
        let mut header_immutable_index_data = vec![];
        let mut hie = IndexEntry::new(tag, (records_count + 1) * -16, IndexData::Bin(Vec::new()));
        hie.num_items = 16;
        hie.write_index(&mut header_immutable_index_data)
            .expect("unabel to write to memory buffer");
        IndexEntry::new(tag, offset, IndexData::Bin(header_immutable_index_data))
    }

    fn from_entries(mut actual_records: Vec<IndexEntry<T>>, region_tag: T) -> Self {
        let mut store = Vec::new();
        for record in &mut actual_records {
            record.offset = store.len() as i32;
            let alignment = record.data.append(&mut store);
            record.offset += alignment as i32;
        }

        let region_tag =
            Self::create_region_tag(region_tag, actual_records.len() as i32, store.len() as i32);
        region_tag.data.append(&mut store);

        let mut all_records = vec![region_tag];

        all_records.append(&mut actual_records);
        let store_size = store.len();

        // TODO dunno if this is necessary yet.
        // if store_size % 8 > 0 {
        //     store_size += 8 - (store_size % 8);
        // }
        let index_header = IndexHeader::new(all_records.len() as u32, store_size as u32);
        Header {
            index_entries: all_records,
            index_header,
            store,
        }
    }
}

impl Header<IndexSignatureTag> {
    fn new_signature_header(size: i32, md5: &[u8], sha1: String) -> Self {
        let offset = 0;
        let entries = vec![
            IndexEntry::new(
                IndexSignatureTag::RPMSIGTAG_SIZE,
                offset,
                IndexData::Int32(vec![size]),
            ),
            IndexEntry::new(
                IndexSignatureTag::RPMSIGTAG_MD5,
                offset,
                IndexData::Bin(md5.to_vec()),
            ),
            IndexEntry::new(
                IndexSignatureTag::RPMSIGTAG_SHA1,
                offset,
                IndexData::StringTag(sha1),
            ),
        ];
        Self::from_entries(entries, IndexSignatureTag::HEADER_SIGNATURES)
    }

    fn parse_signature<I: std::io::BufRead>(
        input: &mut I,
    ) -> Result<Header<IndexSignatureTag>, RPMError> {
        let result = Self::parse(input)?;
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
            let expansion = vec![0; 8 - modulo as usize];
            out.write_all(&expansion)?;
        }
        Ok(())
    }
}

impl Header<IndexTag> {

    pub fn get_payload_format(&self) -> Result<&str, RPMError> {
        self.get_entry_string_data(IndexTag::RPMTAG_PAYLOADFORMAT)
    }

    pub fn get_payload_compressor(&self) -> Result<&str, RPMError> {
        self.get_entry_string_data(IndexTag::RPMTAG_PAYLOADCOMPRESSOR)
    }

    pub fn get_file_checksums(&self) -> Result<&[String], RPMError> {
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
        let (_rest, header_size) = be_u32(rest)?;

        Ok(IndexHeader {
            magic: magic.try_into().unwrap(),
            version: 1,
            num_entries,
            header_size,
        })
    }

    fn write<W: std::io::Write>(&self, out: &mut W) -> Result<(), RPMError> {
        out.write_all(&self.magic)?;
        out.write_all(&self.version.to_be_bytes())?;
        out.write_all(&[0; 4])?;
        out.write_all(&self.num_entries.to_be_bytes())?;
        out.write_all(&self.header_size.to_be_bytes())?;
        Ok(())
    }

    fn new(num_entries: u32, header_size: u32) -> Self {
        IndexHeader {
            magic: HEADER_MAGIC,
            version: 1,
            num_entries,
            header_size,
        }
    }
}

#[derive(Debug, PartialEq)]
struct IndexEntry<T: num::FromPrimitive> {
    tag: T,
    data: IndexData,
    offset: i32,
    num_items: u32,
}

impl<T: num::FromPrimitive + num::ToPrimitive + std::fmt::Debug> IndexEntry<T> {
    // 16 bytes
    fn parse(input: &[u8]) -> Result<(&[u8], Self), RPMError> {
        //first 4 bytes are the tag.
        let (input, raw_tag) = be_u32(input)?;

        let tag: T = num::FromPrimitive::from_u32(raw_tag)
            .ok_or_else(|| RPMError::new(&format!("invalid tag {}", raw_tag)))?;
        //next 4 bytes is the tag type
        let (input, raw_tag_type) = be_u32(input)?;

        // initialize the datatype. Parsing of the data happens later since the store comes after the index section.
        let data = IndexData::from_u32(raw_tag_type)
            .ok_or_else(|| RPMError::new(&format!("invalid tag_type {}", raw_tag_type)))?;

        //  next 4 bytes is the offset relative to the beginning of the store
        let (input, offset) = be_i32(input)?;

        // last 4 bytes are the count that contains the number of data items pointed to by the index entry
        let (rest, num_items) = be_u32(input)?;

        Ok((
            rest,
            IndexEntry {
                tag,
                data,
                offset,
                num_items,
            },
        ))
    }

    fn write_index<W: std::io::Write>(&self, out: &mut W) -> Result<(), RPMError> {
        let mut written = out.write(&self.tag.to_u32().unwrap().to_be_bytes())?;
        written += out.write(&self.data.to_u32().to_be_bytes())?;
        written += out.write(&self.offset.to_be_bytes())?;
        written += out.write(&self.num_items.to_be_bytes())?;
        assert_eq!(16, written, "there should be 16 bytes written");
        Ok(())
    }

    fn new(tag: T, offset: i32, data: IndexData) -> IndexEntry<T> {
        IndexEntry {
            tag,
            offset,
            num_items: data.num_items(),
            data,
        }
    }
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


    fn append(&self, store: &mut Vec<u8>) -> u32 {
        match &self {
            IndexData::Null => 0,
            IndexData::Char(d) => {
                store.extend_from_slice(d);
                0
            }
            IndexData::Int8(d) => {
                for i in d.iter().map(|i| i.to_be_bytes()) {
                    store.push(i[0]);
                }
                0
            }
            IndexData::Int16(d) => {
                // align to 2 bytes

                let alignment = if store.len() % 2 != 0 {
                    store.push(0);
                    1
                } else {
                    0
                };
                let iter = d.iter().flat_map(|item| item.to_be_bytes().to_vec());
                for byte in iter {
                    store.push(byte);
                }
                alignment
            }
            IndexData::Int32(d) => {
                // align to 4 bytes
                let mut alignment = 0;
                while store.len() % 4 > 0 {
                    store.push(0);
                    alignment += 1;
                }
                let iter = d.iter().flat_map(|item| item.to_be_bytes().to_vec());
                for byte in iter {
                    store.push(byte);
                }
                alignment
            }
            IndexData::Int64(d) => {
                // align to 8 bytes
                let mut alignment = 0;
                while store.len() % 8 > 0 {
                    store.push(0);
                    alignment += 1;
                }
                let iter = d.iter().flat_map(|item| item.to_be_bytes().to_vec());
                for byte in iter {
                    store.push(byte);
                }
                alignment
            }
            IndexData::StringTag(d) => {
                store.extend_from_slice(d.as_bytes());
                store.push(0);
                0
            }
            IndexData::Bin(d) => {
                store.extend_from_slice(&d);
                0
            }
            IndexData::StringArray(d) => {
                for item in d {
                    store.extend_from_slice(item.as_bytes());
                    store.push(0);
                }
                0
            }
            IndexData::I18NString(d) => {
                for item in d {
                    store.extend_from_slice(item.as_bytes());
                    store.push(0);
                }
                0
            }
        }
    }



    fn num_items(&self) -> u32 {
        match self {
            IndexData::Null => 0,
            IndexData::Bin(items) => items.len() as u32,
            IndexData::Char(items) => items.len() as u32,
            IndexData::I18NString(items) => items.len() as u32,
            IndexData::StringTag(_) => 1,
            IndexData::StringArray(items) => items.len() as u32,
            IndexData::Int8(items) => items.len() as u32,
            IndexData::Int16(items) => items.len() as u32,
            IndexData::Int32(items) => items.len() as u32,
            IndexData::Int64(items) => items.len() as u32,
        }
    }
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
    fn to_u32(&self) -> u32 {
        match self {
            IndexData::Null => 0,
            IndexData::Char(_) => 1,
            IndexData::Int8(_) => 2,
            IndexData::Int16(_) => 3,
            IndexData::Int32(_) => 4,
            IndexData::Int64(_) => 5,
            IndexData::StringTag(_) => 6,
            IndexData::Bin(_) => 7,

            IndexData::StringArray(_) => 8,
            IndexData::I18NString(_) => 9,
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
    Copy,
    Clone,
    enum_display_derive::Display,
)]
#[allow(non_camel_case_types)]
pub enum IndexTag {
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
    Copy,
    Clone,
    enum_display_derive::Display,
)]
#[allow(non_camel_case_types)]
pub enum IndexSignatureTag {
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

pub struct Dependency {
    dep_name: String,
    sense: u32,
    version: String,
}

impl Dependency {
    pub fn less(dep_name: String, version: String) -> Self {
        Self::new(dep_name, RPMSENSE_LESS, version)
    }

    pub fn less_eq(dep_name: String, version: String) -> Self {
        Self::new(dep_name, RPMSENSE_LESS | RPMSENSE_EQUAL, version)
    }

    pub fn eq(dep_name: String, version: String) -> Self {
        Self::new(dep_name, RPMSENSE_EQUAL, version)
    }

    pub fn greater(dep_name: String, version: String) -> Self {
        Self::new(dep_name, RPMSENSE_GREATER, version)
    }

    pub fn greater_eq(dep_name: String, version: String) -> Self {
        Self::new(dep_name, RPMSENSE_GREATER | RPMSENSE_EQUAL, version)
    }

    pub fn any(dep_name: String) -> Self {
        Self::new(dep_name, RPMSENSE_ANY, "".to_string())
    }

    fn new(dep_name: String, sense: u32, version: String) -> Self {
        Dependency {
            dep_name,
            sense,
            version,
        }
    }
}

const RPMSENSE_ANY: u32 = 0;
const RPMSENSE_LESS: u32 = (1 << 1);
const RPMSENSE_GREATER: u32 = (1 << 2);
const RPMSENSE_EQUAL: u32 = (1 << 3);

// there is no use yet for those constants. But they are part of the official package
// so I will leave them in in case we need them later.

// const RPMSENSE_POSTTRANS: u32 = (1 << 5);
// const RPMSENSE_PREREQ: u32 = (1 << 6);
// const RPMSENSE_PRETRANS: u32 = (1 << 7);
// const RPMSENSE_INTERP: u32 = (1 << 8);
// const RPMSENSE_SCRIPT_PRE: u32 = (1 << 9);
// const RPMSENSE_SCRIPT_POST: u32 = (1 << 10);
// const RPMSENSE_SCRIPT_PREUN: u32 = (1 << 11);
// const RPMSENSE_SCRIPT_POSTUN: u32 = (1 << 12);
// const RPMSENSE_SCRIPT_VERIFY: u32 = (1 << 13);
// const RPMSENSE_FIND_REQUIRES: u32 = (1 << 14);
// const RPMSENSE_FIND_PROVIDES: u32 = (1 << 15);
// const RPMSENSE_TRIGGERIN: u32 = (1 << 16);
// const RPMSENSE_TRIGGERUN: u32 = (1 << 17);
// const RPMSENSE_TRIGGERPOSTUN: u32 = (1 << 18);
// const RPMSENSE_MISSINGOK: u32 = (1 << 19);

// // for some weird reason, centos packages have another value for rpm lib sense. We have to observe this.
// const RPMSENSE_RPMLIB: u32 = (1 << 24); //0o100000012;
// const RPMSENSE_TRIGGERPREIN: u32 = (1 << 25);
// const RPMSENSE_KEYRING: u32 = (1 << 26);
// const RPMSENSE_CONFIG: u32 = (1 << 28);

const RPMFILE_CONFIG: i32 = 1;
const RPMFILE_DOC: i32 = 1 << 1;
// const RPMFILE_DONOTUSE: i32 = (1 << 2);
// const RPMFILE_MISSINGOK: i32 = (1 << 3);
// const RPMFILE_NOREPLACE: i32 = (1 << 4);
// const RPMFILE_SPECFILE: i32 = (1 << 5);
// const RPMFILE_GHOST: i32 = (1 << 6);
// const RPMFILE_LICENSE: i32 = (1 << 7);
// const RPMFILE_README: i32 = (1 << 8);
// const RPMFILE_EXCLUDE: i32 = (1 << 9);

pub struct RPMFileEntry {
    size: i32,
    mode: i16,


    modified_at: i32,
    sha_checksum: String,
    link: String,
    flag: i32,
    user: String,
    group: String,
    base_name: String,
    cpio_path: String,

    content: Option<Vec<u8>>,
}

pub struct RPMError {
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
            nom::Err::Error((_, kind)) | nom::Err::Failure((_, kind)) => RPMError {
                message: kind.description().to_string(),
            },
            nom::Err::Incomplete(_) => RPMError {
                message: "unhandled incomplete".to_string(),
            },
        }
    }
}


pub struct RPMFileOptions {
    destination: String,
    user: String,
    group: String,
    symlink: String,
    mode: i32,
    flag: i32,
    inherit_permissions: bool,
}

impl RPMFileOptions {
    pub fn new<T: Into<String>>(dest: T) -> RPMFileOptionsBuilder {
        RPMFileOptionsBuilder {
            inner: RPMFileOptions {
                destination: dest.into(),
                user: "root".to_string(),
                group: "root".to_string(),
                symlink: "".to_string(),
                mode: 0o100664,
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


pub struct RPMBuilder {
    name: String,
    version: String,
    license: String,
    arch: String,
    uid: Option<u32>,
    gid: Option<u32>,
    desc: String,
    release: String,

    // File entries need to be sorted. The entries need to be in the same order as they come
    // in the cpio payload. Otherwise rpm will not be able to resolve those paths.
    files: std::collections::BTreeMap<String, BTreeMap<String, RPMFileEntry>>,

    requires: Vec<Dependency>,
    obsoletes: Vec<Dependency>,
    provides: Vec<Dependency>,
    conflicts: Vec<Dependency>,

    pre_inst_script: Option<String>,
    post_inst_script: Option<String>,
    pre_uninst_script: Option<String>,
    post_uninst_script: Option<String>,

    changelog_authors: Vec<String>,
    changelog_entries: Vec<String>,
    changelog_times: Vec<i32>,
}


impl RPMBuilder {
    pub fn new(name: &str, version: &str, license: &str, arch: &str, desc: &str) -> Self {
        RPMBuilder {
            name: name.to_string(),
            version: version.to_string(),
            license: license.to_string(),
            arch: arch.to_string(),
            desc: desc.to_string(),
            release: "1".to_string(),
            uid: None,
            gid: None,
            conflicts: Vec::new(),
            provides: Vec::new(),
            obsoletes: Vec::new(),
            requires: Vec::new(),
            pre_inst_script: None,
            post_inst_script: None,
            pre_uninst_script: None,
            post_uninst_script: None,
            files: std::collections::BTreeMap::new(),
            changelog_authors: Vec::new(),
            changelog_entries: Vec::new(),
            changelog_times: Vec::new(),
        }
    }

    pub fn add_changelog_entry<E,F>(mut self,author:E,entry: F, time: i32)-> Self where E: Into<String>,F: Into<String>  {
        self.changelog_authors.push(author.into());
        self.changelog_entries.push(entry.into());
        self.changelog_times.push(time);
        self
    }


    pub fn with_file<T: Into<RPMFileOptions>>(
        mut self,
        source: &str,
        options: T,
    ) -> Result<Self, RPMError> {
        let mut input = std::fs::File::open(source)?;
        let mut content = Vec::new();
        input.read_to_end(&mut content)?;
        let mut options = options.into();
        if options.inherit_permissions {
        options.mode = input.metadata()?.permissions().mode() as i32;
        }
        self.add_data(
            content,
            input
                .metadata()?
                .modified()?
                .duration_since(UNIX_EPOCH)
                .expect("something really wrong with your time")
                .as_secs() as i32,
            options,
        )?;
        Ok(self)
    }

    fn add_data(
        &mut self,
        content: Vec<u8>,
        modified_at: i32,
        options: RPMFileOptions,
    ) -> Result<(), RPMError> {
        let dest = options.destination;
        if !dest.starts_with("./") && !dest.starts_with("/") {
            return Err(RPMError::new(&format!(
                "invalid path {} - needs to start with / or ./",
                dest
            )));
        }

        let pb = std::path::PathBuf::from(dest.clone());

        let parent = pb
            .parent()
            .ok_or_else(|| RPMError::new(&format!("invalid destination path {}", dest)))?;
        let (cpio_path, dir) = if dest.starts_with(".") {
            (
                dest.to_string(),
                format!("/{}/", parent.strip_prefix(".").unwrap().to_string_lossy()),
            )
        } else {
            (
                format!(".{}", dest),
                format!("{}/", parent.to_string_lossy()),
            )
        };

        let mut hasher = sha2::Sha256::default();
        hasher.input(&content);
        let hash_result = hasher.result();
        let sha_checksum = format!("{:x}", hash_result);
        let entry = RPMFileEntry {
            base_name: pb.file_name().unwrap().to_string_lossy().to_string(),
            size: content.len() as i32,
            content: Some(content),
            cpio_path: cpio_path.clone(),
            flag: options.flag,
            user: options.user,
            group: options.group,
            mode: options.mode as i16,
            link: options.symlink,
            modified_at,

            sha_checksum,
        };

        self.files
            .entry(dir)
            .or_insert(BTreeMap::new())
            .insert(cpio_path, entry);
        Ok(())
    }

    pub fn pre_install_script(mut self, content: String) -> Self {
        self.pre_inst_script = Some(content);
        self
    }

    pub fn post_install_script(mut self, content: String) -> Self {
        self.post_inst_script = Some(content);
        self
    }

    pub fn pre_uninstall_script(mut self, content: String) -> Self {
        self.pre_uninst_script = Some(content);
        self
    }

    pub fn post_uninstall_script(mut self, content: String) -> Self {
        self.post_uninst_script = Some(content);
        self
    }

    pub fn release(mut self, release: u16) -> Self {
        self.release = format!("{}", release);
        self
    }

    pub fn requires(mut self, dep: Dependency) -> Self {
        self.requires.push(dep);
        self
    }

    pub fn obsoletes(mut self, dep: Dependency) -> Self {
        self.obsoletes.push(dep);
        self
    }

    pub fn conflicts(mut self, dep: Dependency) -> Self {
        self.conflicts.push(dep);
        self
    }

    pub fn provides(mut self, dep: Dependency) -> Self {
        self.provides.push(dep);
        self
    }

    pub fn build(mut self) -> Result<RPMPackage, RPMError> {
        // signature depends on header and payload. So we build these two first.
        // then the signature. Then we stitch all toghether.
        // Lead is not important. just build it here

        let lead = Lead::new(&self.name);

        let mut content: Vec<u8> = Vec::new();

        let mut compressor = libflate::gzip::Encoder::new(&mut content)?;

        let mut ino_index = 1;


        let mut directories = Vec::new();

        let mut file_sizes = Vec::new();
        let mut file_modes = Vec::new();
        let mut file_rdevs = Vec::new();
        let mut file_mtimes = Vec::new();
        let mut file_hashes = Vec::new();
        let mut file_linktos = Vec::new();
        let mut file_flags = Vec::new();
        let mut file_usernames = Vec::new();
        let mut file_groupnames = Vec::new();
        let mut file_devices = Vec::new();
        let mut file_inodes = Vec::new();
        let mut file_langs = Vec::new();
        let mut file_verify_flags = Vec::new();
        let mut dir_indixes = Vec::new();
        let mut base_names = Vec::new();

        let mut combined_file_sizes = 0;


        for (index, (dir, entries)) in self.files.iter().enumerate() {
            directories.push(dir.to_owned());
            for entry in entries.values() {
                combined_file_sizes += entry.size;
                file_sizes.push(entry.size);
                file_modes.push(entry.mode);
                // I really do not know the difference. It seems like file_rdevice is always 0 and file_device number always 1.
                // Who knows, who cares.
                file_rdevs.push(0);
                file_devices.push(1);
                file_mtimes.push(entry.modified_at);
                file_hashes.push(entry.sha_checksum.to_owned());
                file_linktos.push(entry.link.to_owned());
                file_flags.push(entry.flag);
                file_usernames.push(entry.user.to_owned());
                file_groupnames.push(entry.group.to_owned());
                file_inodes.push(ino_index as i32);
                file_langs.push("".to_string());
                dir_indixes.push(index as i32);
                base_names.push(entry.base_name.to_owned());
                file_verify_flags.push(-1);
                let content = entry.content.to_owned().unwrap();
                let mut writer = cpio::newc::Builder::new(&entry.cpio_path)
                    .mode(entry.mode as u32)
                    .ino(ino_index as u32)
                    .uid(self.uid.unwrap_or(0))
                    .gid(self.gid.unwrap_or(0))
                    .write(&mut compressor, content.len() as u32);

                writer.write_all(&content)?;
                writer.finish()?;

                ino_index += 1;
            }
        }

        self.requires.push(Dependency::any("/bin/sh".to_string()));

        self.provides
            .push(Dependency::eq(self.name.clone(), self.version.clone()));
        self.provides.push(Dependency::eq(
            format!("{}({})", self.name.clone(), self.arch.clone()),
            self.version.clone(),
        ));


        let mut provide_names = Vec::new();
        let mut provide_flags = Vec::new();
        let mut provide_versions = Vec::new();

        for d in self.provides.drain(0..) {
            provide_names.push(d.dep_name);
            provide_flags.push(d.sense as i32);
            provide_versions.push(d.version);
        }

        let mut obsolete_names = Vec::new();
        let mut obsolete_flags = Vec::new();
        let mut obsolete_versions = Vec::new();

        for d in self.obsoletes.drain(0..) {
            obsolete_names.push(d.dep_name);
            obsolete_flags.push(d.sense as i32);
            obsolete_versions.push(d.version);
        }

        let mut require_names = Vec::new();
        let mut require_flags = Vec::new();
        let mut require_versions = Vec::new();

        for d in self.requires.drain(0..) {
            require_names.push(d.dep_name);
            require_flags.push(d.sense as i32);
            require_versions.push(d.version);
        }

        let mut conflicts_names = Vec::new();
        let mut conflicts_flags = Vec::new();
        let mut conflicts_versions = Vec::new();

        for d in self.conflicts.drain(0..) {
            conflicts_names.push(d.dep_name);
            conflicts_flags.push(d.sense as i32);
            conflicts_versions.push(d.version);
        }

        let offset = 0;
        let mut actual_records = vec![
            IndexEntry::new(
                IndexTag::RPMTAG_HEADERI18NTABLE,
                offset,
                IndexData::StringTag("C".to_string()),
            ),

            IndexEntry::new(
                IndexTag::RPMTAG_NAME,
                offset,
                IndexData::StringTag(self.name),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_VERSION,
                offset,
                IndexData::StringTag(self.version),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_RELEASE,
                offset,
                IndexData::StringTag(self.release),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_DESCRIPTION,
                offset,
                IndexData::StringTag(self.desc.clone()),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_SUMMARY,
                offset,
                IndexData::StringTag(self.desc),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_SIZE,
                offset,
                IndexData::Int32(vec![combined_file_sizes]),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_LICENSE,
                offset,
                IndexData::StringTag(self.license),
            ),
            // https://fedoraproject.org/wiki/RPMGroups
            // IndexEntry::new(IndexTag::RPMTAG_GROUP, offset, IndexData::I18NString(group)),
            IndexEntry::new(
                IndexTag::RPMTAG_OS,
                offset,
                IndexData::StringTag("linux".to_string()),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_GROUP,
                offset,
                IndexData::I18NString(vec!["Unspecified".to_string()]),
            ),

            IndexEntry::new(
                IndexTag::RPMTAG_ARCH,
                offset,
                IndexData::StringTag(self.arch),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_PAYLOADFORMAT,
                offset,
                IndexData::StringTag("cpio".to_string()),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_PAYLOADCOMPRESSOR,
                offset,
                IndexData::StringTag("gzip".to_string()),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_PAYLOADFLAGS,
                offset,
                IndexData::StringTag("2".to_string()),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_FILESIZES,
                offset,
                IndexData::Int32(file_sizes),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_FILEMODES,
                offset,
                IndexData::Int16(file_modes),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_FILERDEVS,
                offset,
                IndexData::Int16(file_rdevs),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_FILEMTIMES,
                offset,
                IndexData::Int32(file_mtimes),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_FILEDIGESTS,
                offset,
                IndexData::StringArray(file_hashes),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_FILELINKTOS,
                offset,
                IndexData::StringArray(file_linktos),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_FILEFLAGS,
                offset,
                IndexData::Int32(file_flags),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_FILEUSERNAME,
                offset,
                IndexData::StringArray(file_usernames),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_FILEGROUPNAME,
                offset,
                IndexData::StringArray(file_groupnames),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_FILEDEVICES,
                offset,
                IndexData::Int32(file_devices),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_FILEINODES,
                offset,
                IndexData::Int32(file_inodes),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_DIRINDEXES,
                offset,
                IndexData::Int32(dir_indixes),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_FILELANGS,
                offset,
                IndexData::StringArray(file_langs),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_FILEDIGESTALGO,
                offset,
                IndexData::Int32(vec![8]),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_FILEVERIFYFLAGS,
                offset,
                IndexData::Int32(file_verify_flags),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_BASENAMES,
                offset,
                IndexData::StringArray(base_names),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_DIRNAMES,
                offset,
                IndexData::StringArray(directories),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_PROVIDENAME,
                offset,
                IndexData::StringArray(provide_names),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_PROVIDEVERSION,
                offset,
                IndexData::StringArray(provide_versions),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_PROVIDEFLAGS,
                offset,
                IndexData::Int32(provide_flags),
            ),
        ];

        if !self.changelog_authors.is_empty() {
            actual_records.push(
                IndexEntry::new(
                    IndexTag::RPMTAG_CHANGELOGNAME,
                    offset,
                    IndexData::StringArray(self.changelog_authors),
                )
            );
            actual_records.push(
                IndexEntry::new(
                    IndexTag::RPMTAG_CHANGELOGTEXT,
                    offset,
                    IndexData::StringArray(self.changelog_entries),
                )
            );
            actual_records.push(
                IndexEntry::new(
                    IndexTag::RPMTAG_CHANGELOGTIME,
                    offset,
                    IndexData::Int32(self.changelog_times),
                )
            );
        }

        if !obsolete_flags.is_empty() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_OBSOLETENAME,
                offset,
                IndexData::StringArray(obsolete_names),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_OBSOLETEVERSION,
                offset,
                IndexData::StringArray(obsolete_versions),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_OBSOLETEFLAGS,
                offset,
                IndexData::Int32(obsolete_flags),
            ));
        }

        if !require_flags.is_empty() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_REQUIRENAME,
                offset,
                IndexData::StringArray(require_names),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_REQUIREVERSION,
                offset,
                IndexData::StringArray(require_versions),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_REQUIREFLAGS,
                offset,
                IndexData::Int32(require_flags),
            ));
        }

        if !conflicts_flags.is_empty() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_CONFLICTNAME,
                offset,
                IndexData::StringArray(conflicts_names),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_CONFLICTVERSION,
                offset,
                IndexData::StringArray(conflicts_versions),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_CONFLICTFLAGS,
                offset,
                IndexData::Int32(conflicts_flags),
            ));
        }

        if self.pre_inst_script.is_some() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_PREIN,
                offset,
                IndexData::StringTag(self.pre_inst_script.unwrap()),
            ));
        }
        if self.post_inst_script.is_some() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_POSTIN,
                offset,
                IndexData::StringTag(self.post_inst_script.unwrap()),
            ));
        }

        if self.pre_uninst_script.is_some() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_PREUN,
                offset,
                IndexData::StringTag(self.pre_uninst_script.unwrap()),
            ));
        }

        if self.post_uninst_script.is_some() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_POSTUN,
                offset,
                IndexData::StringTag(self.post_uninst_script.unwrap()),
            ));
        }

        let header = Header::from_entries(actual_records, IndexTag::RPMTAG_HEADERIMMUTABLE);

        //those parts seem to break on fedora installations, but it does not seem to matter for centos.
        // if it turns out that those parts are not really required, we will delete the following comments

        // self.requires.push(Dependency::rpm_lib(
        //     "rpmlib(VersionedDependencies)".to_string(),
        //     "3.0.3-1".to_string(),
        // ));

        // self.requires.push(Dependency::rpm_lib(
        //     "rpmlib(PayloadFilesHavePrefix)".to_string(),
        //     "4.0-1".to_string(),
        // ));

        // self.requires.push(Dependency::rpm_lib(
        //     "rpmlib(CompressedFileNames)".to_string(),
        //     "3.0.4-1".to_string(),
        // ));

        // self.requires.push(Dependency::rpm_lib(
        //     "rpmlib(PayloadIsXz)".to_string(),
        //     "5.2-1".to_string(),
        // ));
        // self.requires.push(Dependency::rpm_lib(
        //     "rpmlib(FileDigests)".to_string(),
        //     "4.6.0-1".to_string(),
        // ));

        let mut header_bytes = Vec::new();
        header.write(&mut header_bytes)?;

        compressor = cpio::newc::trailer(compressor)?;
        compressor.finish().into_result()?;

        let signature_size = header_bytes.len() + content.len();
        let mut hasher = md5::Md5::default();

        hasher.input(&header_bytes);
        hasher.input(&content);

        let hash_result = hasher.result();

        let signature_md5 = hash_result.as_slice();

        let header_sha1 = sha1::Sha1::from(&header_bytes);

        let signature_header = Header::new_signature_header(
            signature_size as i32,
            signature_md5,
            header_sha1.digest().to_string(),
        );

        let metadata = RPMPackageMetadata {
            lead,
            signature: signature_header,
            header,
        };
        let pkg = RPMPackage { metadata, content };
        Ok(pkg)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::io::prelude::*;

    #[test]
    fn test_header() -> Result<(), Box<std::error::Error>> {
        let d = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let mut rpm_file_path = d.clone();
        rpm_file_path.push("test_assets/389-ds-base-devel-1.3.8.4-15.el7.x86_64.rpm");
        let rpm_file = std::fs::File::open(rpm_file_path).expect("should be able to open rpm file");
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

        assert_eq!(
            package.metadata.signature.index_header,
            signature.index_header
        );

        for i in 0..signature.index_entries.len() {
            assert_eq!(
                signature.index_entries[i],
                package.metadata.signature.index_entries[i]
            );
        }
        assert_eq!(
            package.metadata.signature.index_entries,
            signature.index_entries
        );

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

    #[test]
    fn test_builder() -> Result<(), Box<std::error::Error>> {
        let d = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let mut cargo_file = d.clone();
        cargo_file.push("Cargo.toml");

        let mut out_file = d.clone();
        out_file.push("out/test.rpm");
        let mut f = std::fs::File::create(out_file)?;
        let pkg = RPMBuilder::new("test", "1.0.0", "MIT", "x86_64", "some package")

            .with_file(
                cargo_file.to_str().unwrap(),
                RPMFileOptions::new("/etc/foobar/foo.toml"),
            )?
            .with_file(
                cargo_file.to_str().unwrap(),
                RPMFileOptions::new("/etc/foobar/bazz.toml"),
            )?
            .with_file(
                cargo_file.to_str().unwrap(),
                RPMFileOptions::new("/etc/foobar/hugo/bazz.toml").mode(0o100777).is_config(),
            )?
            .with_file(
                cargo_file.to_str().unwrap(),
                RPMFileOptions::new("/etc/foobar/hugo/aa.toml"),
            )?
            .with_file(
                cargo_file.to_str().unwrap(),
                RPMFileOptions::new("/var/honollulu/bazz.toml"),
            )?
            .with_file(
                cargo_file.to_str().unwrap(),
                RPMFileOptions::new("/etc/Cargo.toml"),
            )?
            .pre_install_script("echo preinst".to_string())
            .add_changelog_entry("me", "was awesome, eh?", 123123123)
            .add_changelog_entry("you", "yeah, it was", 12312312)
            // .requires(Dependency::any("wget".to_string()))
            .build()?;

        pkg.write(&mut f)?;


        let mut handles = Vec::new();
        for image in vec!["fedora:30", "centos:7"] {
            let mut docker_cmd = std::process::Command::new("docker");
            let mut out_path = d.clone();
            out_path.push("out");
            docker_cmd.args(vec![
                "run",
                "--rm",
                "-v",
                &format!("{}:/out:z", out_path.to_string_lossy().to_string()),
                image,
                "yum",
                "--disablerepo=*",
                "localinstall",
                "-y",
                "/out/test.rpm",
            ]);
            let handle = docker_cmd.spawn()?;
            handles.push(handle);
        }

        for mut handle in handles {
            let status = handle.wait()?;
            assert!(status.success());
        }
        Ok(())
    }

    #[test]
    fn test_region_tag() -> Result<(), Box<std::error::Error>> {
        let region_entry = Header::create_region_tag(IndexSignatureTag::HEADER_SIGNATURES, 2, 400);

        let data = match region_entry.data {
            IndexData::Bin(d) => d,
            _ => return Err(Box::new(RPMError::new("should be bin"))),
        };

        let (_, entry) = IndexEntry::<IndexSignatureTag>::parse(&data)?;

        assert_eq!(entry.tag, IndexSignatureTag::HEADER_SIGNATURES);
        assert_eq!(entry.data.to_u32(), IndexData::Bin(Vec::new()).to_u32());
        assert_eq!(-48, entry.offset);

        Ok(())
    }

}

