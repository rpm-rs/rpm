use nom::bytes::complete;
use nom::number::complete::{be_i16, be_i32, be_i64, be_i8, be_u16, be_u32, be_u8};

use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryInto;
use std::fmt;
use std::fmt::Display;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use std::time::UNIX_EPOCH;

mod errors;
pub use crate::errors::*;

pub mod crypto;

mod constants;
pub use crate::constants::*;

#[cfg(feature = "signing-meta")]
mod signature;
#[cfg(feature = "signing-meta")]
mod signature_builder;

#[cfg(feature = "signing-meta")]
pub use crate::signature::*;
#[cfg(feature = "signing-meta")]
pub use crate::signature_builder::*;

pub struct RPMPackage {
    /// Header and metadata structures.
    ///
    /// Contains the constant lead as well as the metadata store.
    pub metadata: RPMPackageMetadata,
    /// The compressed or uncompressed files.
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

    // TODO allow passing an external signer/verifier

    /// sign all headers (except for the lead) using an external key and store it as the initial header
    #[cfg(feature = "signing-meta")]
    pub fn sign<S>(&mut self, secret_key: &[u8]) -> Result<(), RPMError>
    where
        S: crypto::Signing<crypto::algorithm::RSA, Signature = Vec<u8>>
            + crypto::KeyLoader<crypto::key::Secret>,
    {
        // create a temporary byte repr of the header
        // and re-create all hashes
        let mut header_bytes = Vec::<u8>::with_capacity(1024);
        self.metadata.header.write(&mut header_bytes)?;

        let mut header_and_content_bytes =
        Vec::with_capacity(header_bytes.len() + self.content.len());
        header_and_content_bytes.extend(header_bytes.as_slice());
        header_and_content_bytes.extend(self.content.as_slice());

        let mut hasher = md5::Md5::default();

        hasher.input(&header_and_content_bytes);

        let hash_result = hasher.result();

        let digest_md5 = hash_result.as_slice();

        let digest_sha1 = sha1::Sha1::from(&header_bytes);
        let digest_sha1 = digest_sha1.digest();

        let signer = S::load_from(secret_key)?;

        let rsa_signature_spanning_header_only = signer.sign(header_bytes.as_slice())?;

        let rsa_signature_spanning_header_and_archive = signer.sign(header_and_content_bytes.as_slice())?;

        // TODO FIXME verify this is the size we want, I don't think it is
        // TODO maybe use signature_size instead of size
        self.metadata.signature = Header::<IndexSignatureTag>::new_signature_header(
            header_and_content_bytes.len() as i32,
            digest_md5,
            digest_sha1.to_string(),
            rsa_signature_spanning_header_only.as_slice(),
            rsa_signature_spanning_header_and_archive.as_slice(),
        );

        Ok(())
    }

    /// Verify the signature as present within the RPM package.
    ///
    ///
    #[cfg(feature = "signing-meta")]
    pub fn verify_signature<V>(&self, public_key: &[u8]) -> Result<(), RPMError>
    where
        V: crypto::Verifying<crypto::algorithm::RSA, Signature = Vec<u8>>
            + crypto::KeyLoader<crypto::key::Public>,
    {
        // TODO retval should be SIGNATURE_VERIFIED or MISMATCH, not just an error

        let mut header_bytes = Vec::<u8>::with_capacity(1024);
        self.metadata.header.write(&mut header_bytes)?;

        let signature_header_only = self
            .metadata
            .signature
            .get_entry_binary_data(IndexSignatureTag::RPMSIGTAG_RSA)
            .map_err(|e| {
                format!("Missing header-only signature / RPMSIGTAG_RSA: {:?}", e)
            })?;

        crate::crypto::echo_signature("signature_header(header only)", signature_header_only);

        let signature_header_and_content = self
            .metadata
            .signature
            .get_entry_binary_data(IndexSignatureTag::RPMSIGTAG_PGP)
            .map_err(|e| {
                format!("Missing header+content signature / RPMSIGTAG_PGP: {:?}", e)
            })?;

        crate::crypto::echo_signature(
            "signature_header(header and content)",
            signature_header_and_content,
        );

        let verifier = V::load_from(public_key)?;
        verifier.verify(header_bytes.as_slice(), signature_header_only)
            .map_err(|e| { format!("Failed to verify header-only signature / RPMSIGTAG_RSA: {:?}", e) })?;

        let mut header_and_content_bytes =
            Vec::with_capacity(header_bytes.len() + self.content.len());
        header_and_content_bytes.extend(header_bytes);
        header_and_content_bytes.extend(self.content.as_slice());

        verifier.verify(
            header_and_content_bytes.as_slice(),
            signature_header_and_content,
        )
        .map_err(|e| { format!("Failed to verify header+content signature / RPMSIGTAG_PGP: {:?}", e) })?;

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

pub trait Tag:
    num::FromPrimitive + num::ToPrimitive + PartialEq + Display + std::fmt::Debug + Copy
{
}

impl<T> Tag for T where
    T: num::FromPrimitive + num::ToPrimitive + PartialEq + Display + std::fmt::Debug + Copy
{
}

#[derive(Debug, PartialEq)]
pub struct Header<T: num::FromPrimitive> {
    index_header: IndexHeader,
    index_entries: Vec<IndexEntry<T>>,
    store: Vec<u8>,
}

impl<T> Header<T>
where
    T: Tag,
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
        self.index_entries
            .iter()
            .find(|entry| &entry.tag == tag)
            .ok_or_else(|| RPMError::new(&format!("unable to find Tag {}", tag)))
    }

    fn get_entry_binary_data(&self, tag: T) -> Result<&[u8], RPMError> {
        let entry = self.find_entry_or_err(&tag)?;
        entry.data.binary().ok_or_else(|| {
            RPMError::new(&format!(
                "tag {} has datatype {}, not string",
                entry.tag, entry.data,
            ))
        })
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

    fn get_entry_int_data(&self, tag: T) -> Result<i32, RPMError> {
        let entry = self.find_entry_or_err(&tag)?;
        entry.data.int().ok_or_else(|| {
            RPMError::new(&format!(
                "tag {} has datatype {}, not i32",
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

    pub(crate) fn from_entries(mut actual_records: Vec<IndexEntry<T>>, region_tag: T) -> Self {
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
    /// creates a new full signature header
    ///
    /// `size` is combined size of header, header store and the payload
    ///
    /// PGP and RSA tags expect signatures according to [RFC2440](https://tools.ietf.org/html/rfc2440)
    fn new_signature_header(
        size: i32,
        md5sum: &[u8],
        sha1: String,
        rsa_spanning_header: &[u8],
        rsa_spanning_header_and_archive: &[u8],
    ) -> Self {
        SignatureHeaderBuilder::new()
            .add_digest(sha1.as_str(), md5sum)
            .add_signature(rsa_spanning_header, rsa_spanning_header_and_archive)
            .build(size)
    }

    pub fn builder() -> SignatureHeaderBuilder<Empty> {
        SignatureHeaderBuilder::<Empty>::new()
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

    pub fn get_name(&self) -> Result<&str, RPMError> {
        self.get_entry_string_data(IndexTag::RPMTAG_NAME)
    }

    pub fn get_epoch(&self) -> Result<i32, RPMError> {
        self.get_entry_int_data(IndexTag::RPMTAG_EPOCH)
    }

    pub fn get_version(&self) -> Result<&str, RPMError> {
        self.get_entry_string_data(IndexTag::RPMTAG_VERSION)
    }

    pub fn get_release(&self) -> Result<&str, RPMError> {
        self.get_entry_string_data(IndexTag::RPMTAG_RELEASE)
    }

    pub fn get_arch(&self) -> Result<&str, RPMError> {
        self.get_entry_string_data(IndexTag::RPMTAG_ARCH)
    }
}

#[derive(Debug, PartialEq)]
struct IndexHeader {
    /// rpm specific magic header
    magic: [u8; 3],
    /// rpm version number, always 1
    version: u8,
    /// number of header entries
    num_entries: u32,
    /// total header size excluding the fixed part ( I think )
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
                "unsupported Version {} - only header version 1 is supported",
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

    fn int(&self) -> Option<i32> {
        match self {
            IndexData::Int32(s) => {
                if !s.is_empty() {
                    Some(s[0])
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn string_array(&self) -> Option<&[String]> {
        match self {
            IndexData::StringArray(d) | IndexData::I18NString(d) => Some(&d),
            _ => None,
        }
    }

    fn binary(&self) -> Option<&[u8]> {
        match self {
            IndexData::Bin(d) => Some(d.as_slice()),
            _ => None,
        }
    }
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

const RPMSENSE_ANY: u32 = 0;
const RPMSENSE_LESS: u32 = 1 << 1;
const RPMSENSE_GREATER: u32 = 1 << 2;
const RPMSENSE_EQUAL: u32 = 1 << 3;

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
    dir: String,
    content: Option<Vec<u8>>,
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

pub struct RPMBuilder {
    name: String,
    epoch: i32,
    version: String,
    license: String,
    arch: String,
    uid: Option<u32>,
    gid: Option<u32>,
    desc: String,
    release: String,

    // File entries need to be sorted. The entries need to be in the same order as they come
    // in the cpio payload. Otherwise rpm will not be able to resolve those paths.
    // key is the directory, values are complete paths
    files: std::collections::BTreeMap<String, RPMFileEntry>,
    directories: std::collections::BTreeSet<String>,
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
    compressor: Compressor,
}

pub enum Compressor {
    None(Vec<u8>),
    Gzip(libflate::gzip::Encoder<Vec<u8>>),
}

impl Write for Compressor {
    fn write(&mut self, content: &[u8]) -> Result<usize, std::io::Error> {
        match self {
            Compressor::None(data) => data.write(content),
            Compressor::Gzip(encoder) => encoder.write(content),
        }
    }
    fn flush(&mut self) -> Result<(), std::io::Error> {
        match self {
            Compressor::None(data) => data.flush(),
            Compressor::Gzip(encoder) => encoder.flush(),
        }
    }
}

impl Compressor {
    pub fn from_str(raw: &str) -> Result<Self, RPMError> {
        match raw {
            "none" => Ok(Compressor::None(Vec::new())),
            "gzip" => Ok(Compressor::Gzip(libflate::gzip::Encoder::new(Vec::new())?)),
            _ => Err(RPMError::new(&format!("unknown compressor type {}", raw))),
        }
    }
    fn finish_compression(self) -> Result<Vec<u8>, RPMError> {
        match self {
            Compressor::None(data) => Ok(data),
            Compressor::Gzip(encoder) => Ok(encoder.finish().into_result()?),
        }
    }

    fn get_details(&self) -> Option<CompressionDetails> {
        match self {
            Compressor::None(_) => None,
            Compressor::Gzip(_) => Some(CompressionDetails {
                compression_level: "9",
                compression_name: "gzip",
            }),
        }
    }
}

struct CompressionDetails {
    compression_level: &'static str,
    compression_name: &'static str,
}

impl RPMBuilder {
    pub fn new(name: &str, version: &str, license: &str, arch: &str, desc: &str) -> Self {
        RPMBuilder {
            name: name.to_string(),
            epoch: 0,
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
            files: BTreeMap::new(),
            changelog_authors: Vec::new(),
            changelog_entries: Vec::new(),
            changelog_times: Vec::new(),
            compressor: Compressor::None(Vec::new()),
            directories: BTreeSet::new(),
        }
    }

    pub fn epoch(mut self, epoch: i32) -> Self {
        self.epoch = epoch;
        self
    }

    pub fn compression(mut self, comp: Compressor) -> Self {
        self.compressor = comp;
        self
    }

    pub fn add_changelog_entry<E, F>(mut self, author: E, entry: F, time: i32) -> Self
    where
        E: Into<String>,
        F: Into<String>,
    {
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
        if options.inherit_permissions && cfg!(unix) {
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
        if !dest.starts_with("./") && !dest.starts_with('/') {
            return Err(RPMError::new(&format!(
                "invalid path {} - needs to start with / or ./",
                dest
            )));
        }

        let pb = std::path::PathBuf::from(dest.clone());

        let parent = pb
            .parent()
            .ok_or_else(|| RPMError::new(&format!("invalid destination path {}", dest)))?;
        let (cpio_path, dir) = if dest.starts_with('.') {
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
            flag: options.flag,
            user: options.user,
            group: options.group,
            mode: options.mode as i16,
            link: options.symlink,
            modified_at,
            dir: dir.clone(),
            sha_checksum,
        };

        self.directories.insert(dir);
        self.files.entry(cpio_path).or_insert(entry);
        Ok(())
    }

    pub fn pre_install_script<T: Into<String>>(mut self, content: T) -> Self {
        self.pre_inst_script = Some(content.into());
        self
    }

    pub fn post_install_script<T: Into<String>>(mut self, content: T) -> Self {
        self.post_inst_script = Some(content.into());
        self
    }

    pub fn pre_uninstall_script<T: Into<String>>(mut self, content: T) -> Self {
        self.pre_uninst_script = Some(content.into());
        self
    }

    pub fn post_uninstall_script<T: Into<String>>(mut self, content: T) -> Self {
        self.post_uninst_script = Some(content.into());
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

    /// build without a signature
    ///
    /// ignores a present key, if any
    pub fn build(self) -> Result<RPMPackage, RPMError> {
        let (lead, header_idx_tag, content) = self.prepare_data()?;

        let mut header = Vec::with_capacity(128);
        header_idx_tag.write(&mut header)?;
        let header = header;

        let (
            header_digest_sha1,
            header_and_content_digest_md5,
        ) = Self::derive_hashes(header.as_slice(), content.as_slice())?;

        let header_and_content_len = header.len() + content.len();

        let digest_header = Header::<IndexSignatureTag>::builder()
            .add_digest(
                header_digest_sha1.as_str(),
                header_and_content_digest_md5.as_slice(),
            )
            .build(header_and_content_len as i32);

        let metadata = RPMPackageMetadata {
            lead,
            signature: digest_header,
            header: header_idx_tag,
        };
        let pkg = RPMPackage { metadata, content };
        Ok(pkg)
    }

    /// use an external signer to sing and build
    ///
    /// See `crypto::Signing` for more details.
    #[cfg(feature = "signing-meta")]
    pub fn build_and_sign<S>(self, signer: S) -> Result<RPMPackage, RPMError>
    where
        S: crypto::Signing<crate::crypto::algorithm::RSA>,
    {
        let (lead, header_idx_tag, content) = self.prepare_data()?;

        let mut header = Vec::with_capacity(128);
        header_idx_tag.write(&mut header)?;
        let header = header;

        let (
            header_digest_sha1,
            header_and_content_digest_md5,
        ) = Self::derive_hashes(header.as_slice(), content.as_slice())?;

        let header_and_content_len = header.len() + content.len();

        let builder = Header::<IndexSignatureTag>::builder().add_digest(
            header_digest_sha1.as_str(),
            header_and_content_digest_md5.as_slice(),
        );

        let signature_header = {
            let rsa_sig_header_only = signer.sign(header.as_slice()).map_err(|_e| {
                dbg!(_e);
                RPMError::new("Failed to create signature for headers")
            })?;

            let mut concatenated = Vec::with_capacity(header.len() + content.len());
            concatenated.extend(header.as_slice());
            concatenated.extend(content.as_slice());
            let rsa_sig_header_and_archive =
                signer.sign(concatenated.as_slice()).map_err(|_e| {
                    dbg!(_e);
                    RPMError::new("Failed to create signature based for headers and content")
                })?;

            builder
                .add_signature(
                    rsa_sig_header_only.as_ref(),
                    rsa_sig_header_and_archive.as_ref(),
                )
                .build(header_and_content_len as i32)
        };

        let metadata = RPMPackageMetadata {
            lead,
            signature: signature_header,
            header: header_idx_tag,
        };
        let pkg = RPMPackage { metadata, content };
        Ok(pkg)
    }

    /// use prepared data but make sure the signatures are
    fn derive_hashes(
        header: &[u8],
        content: &[u8],
    ) -> Result<(String, Vec<u8>), RPMError> {
        // accross header index and content (compressed or uncompressed, depends on configuration)
        let mut hasher = md5::Md5::default();
        hasher.input(&header);
        hasher.input(&content);
        let digest_md5 = hasher.result();
        let digest_md5 = digest_md5.as_slice();

        // header only, not the lead, just the header index
        let digest_sha1 = sha1::Sha1::from(&header);
        let digest_sha1 = digest_sha1.digest();
        let digest_sha1 = digest_sha1.to_string();

        Ok((
            digest_sha1,
            digest_md5.to_vec(),
        ))
    }

    /// prepapre all rpm headers including content
    fn prepare_data(mut self) -> Result<(Lead, Header<IndexTag>, Vec<u8>), RPMError> {
        // signature depends on header and payload. So we build these two first.
        // then the signature. Then we stitch all toghether.
        // Lead is not important. just build it here

        let lead = Lead::new(&self.name);

        let mut ino_index = 1;

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

        for (cpio_path, entry) in self.files.iter() {
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
            let index = self
                .directories
                .iter()
                .position(|d| d == &entry.dir)
                .unwrap();
            dir_indixes.push(index as i32);
            base_names.push(entry.base_name.to_owned());
            file_verify_flags.push(-1);
            let content = entry.content.to_owned().unwrap();
            let mut writer = cpio::newc::Builder::new(&cpio_path)
                .mode(entry.mode as u32)
                .ino(ino_index as u32)
                .uid(self.uid.unwrap_or(0))
                .gid(self.gid.unwrap_or(0))
                .write(&mut self.compressor, content.len() as u32);

            writer.write_all(&content)?;
            writer.finish()?;

            ino_index += 1;
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
                IndexTag::RPMTAG_EPOCH,
                offset,
                IndexData::Int32(vec![self.epoch]),
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
                IndexData::StringArray(self.directories.into_iter().collect()),
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

        let possible_compression_details = self.compressor.get_details();

        if possible_compression_details.is_some() {
            let details = possible_compression_details.unwrap();
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_PAYLOADCOMPRESSOR,
                offset,
                IndexData::StringTag(details.compression_name.to_string()),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_PAYLOADFLAGS,
                offset,
                IndexData::StringTag(details.compression_level.to_string()),
            ));
        }

        if !self.changelog_authors.is_empty() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_CHANGELOGNAME,
                offset,
                IndexData::StringArray(self.changelog_authors),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_CHANGELOGTEXT,
                offset,
                IndexData::StringArray(self.changelog_entries),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_CHANGELOGTIME,
                offset,
                IndexData::Int32(self.changelog_times),
            ));
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

        self.compressor = cpio::newc::trailer(self.compressor)?;
        let content = self.compressor.finish_compression()?;

        Ok((lead, header, content))
    }
}

#[cfg(test)]
mod tests2 {
    use super::*;

    #[test]
    fn signature_header_build() {
        let size: i32 = 209348;
        let md5sum: &[u8] = &[22u8; 16];
        let sha1: String = "5A884F0CB41EC3DA6D6E7FC2F6AB9DECA8826E8D".to_owned();
        let rsa_spanning_header: &[u8] = b"111222333444";
        let rsa_spanning_header_and_archive: &[u8] = b"7777888899990000";

        let truth = {
            let offset = 0;
            let entries = vec![
                IndexEntry::new(
                    IndexSignatureTag::RPMSIGTAG_SIZE,
                    offset,
                    IndexData::Int32(vec![size]),
                ),
                // TODO consider dropping md5 in favour of sha256
                IndexEntry::new(
                    IndexSignatureTag::RPMSIGTAG_MD5,
                    offset,
                    IndexData::Bin(md5sum.to_vec()),
                ),
                IndexEntry::new(
                    IndexSignatureTag::RPMSIGTAG_SHA1,
                    offset,
                    IndexData::StringTag(sha1.clone()),
                ),
                IndexEntry::new(
                    IndexSignatureTag::RPMSIGTAG_RSA,
                    offset,
                    IndexData::Bin(rsa_spanning_header.to_vec()),
                ),
                IndexEntry::new(
                    IndexSignatureTag::RPMSIGTAG_PGP,
                    offset,
                    IndexData::Bin(rsa_spanning_header_and_archive.to_vec()),
                ),
            ];
            Header::<IndexSignatureTag>::from_entries(entries, IndexSignatureTag::HEADER_SIGNATURES)
        };

        let built = Header::<IndexSignatureTag>::new_signature_header(
            size,
            md5sum,
            sha1.clone(),
            rsa_spanning_header,
            rsa_spanning_header_and_archive,
        );

        assert_eq!(built, truth);
    }
}

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "test-with-podman"))]
mod tests_validate;
