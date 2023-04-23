use nom::bytes::complete;
use nom::number::complete::{be_i32, be_u16, be_u32, be_u64, be_u8};

#[cfg(feature = "async-futures")]
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::constants::{self, *};
use std::fmt;
use std::path::PathBuf;

use super::*;
use crate::errors::*;

#[derive(Debug, PartialEq)]
pub struct Header<T: Tag> {
    pub(crate) index_header: IndexHeader,
    pub(crate) index_entries: Vec<IndexEntry<T>>,
    pub(crate) store: Vec<u8>,
}

impl<T> Header<T>
where
    T: Tag,
{
    #[cfg(feature = "async-futures")]
    pub(crate) async fn parse_async<I: AsyncRead + Unpin>(
        input: &mut I,
    ) -> Result<Header<T>, RPMError> {
        let mut buf: [u8; 16] = [0; 16];
        input.read_exact(&mut buf).await?;
        let index_header = IndexHeader::parse(&buf)?;
        // read rest of header => each index consists of 16 bytes. The index header knows how large the store is.
        let mut buf = vec![0; (index_header.header_size + index_header.num_entries * 16) as usize];
        input.read_exact(&mut buf).await?;
        Self::parse_header(index_header, &buf[..])
    }

    fn parse_header(index_header: IndexHeader, mut bytes: &[u8]) -> Result<Header<T>, RPMError> {
        // parse all entries
        let mut entries: Vec<IndexEntry<T>> = Vec::new();
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
                    parse_entry_data_number(remaining, entry.num_items, ints, be_u8)?;
                }
                IndexData::Int16(ref mut ints) => {
                    parse_entry_data_number(remaining, entry.num_items, ints, be_u16)?;
                }
                IndexData::Int32(ref mut ints) => {
                    parse_entry_data_number(remaining, entry.num_items, ints, be_u32)?;
                }
                IndexData::Int64(ref mut ints) => {
                    parse_entry_data_number(remaining, entry.num_items, ints, be_u64)?;
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

    pub(crate) fn parse<I: std::io::BufRead>(input: &mut I) -> Result<Header<T>, RPMError> {
        let mut buf: [u8; 16] = [0; 16];
        input.read_exact(&mut buf)?;
        let index_header = IndexHeader::parse(&buf)?;
        // read rest of header => each index consists of 16 bytes. The index header knows how large the store is.
        let mut buf = vec![0; (index_header.header_size + index_header.num_entries * 16) as usize];
        input.read_exact(&mut buf)?;
        Self::parse_header(index_header, &buf[..])
    }

    #[cfg(feature = "async-futures")]
    pub(crate) async fn write_async<W: AsyncWrite + Unpin>(
        &self,
        out: &mut W,
    ) -> Result<(), RPMError> {
        self.index_header.write_async(out).await?;
        for entry in &self.index_entries {
            entry.write_index_async(out).await?;
        }
        out.write_all(&self.store).await?;
        Ok(())
    }

    pub(crate) fn write<W: std::io::Write>(&self, out: &mut W) -> Result<(), RPMError> {
        self.index_header.write(out)?;
        for entry in &self.index_entries {
            entry.write_index(out)?;
        }
        out.write_all(&self.store)?;
        Ok(())
    }

    pub(crate) fn find_entry_or_err(&self, tag: T) -> Result<&IndexEntry<T>, RPMError> {
        self.index_entries
            .iter()
            .find(|entry| entry.tag == tag)
            .ok_or_else(|| RPMError::TagNotFound(tag.to_string()))
        // @todo: this could be more efficient, if the tag is an integer, we can just pass around
        // an integer, and the name of the tag (or "unknown") can be easily derived from that
    }

    pub fn get_entry_data_as_binary(&self, tag: T) -> Result<&[u8], RPMError> {
        let entry = self.find_entry_or_err(tag)?;
        entry
            .data
            .as_binary()
            .ok_or_else(|| RPMError::UnexpectedTagDataType {
                expected_data_type: "binary",
                actual_data_type: entry.data.to_string(),
                tag: entry.tag.to_string(),
            })
    }

    pub fn get_entry_data_as_string(&self, tag: T) -> Result<&str, RPMError> {
        let entry = self.find_entry_or_err(tag)?;
        entry
            .data
            .as_str()
            .ok_or_else(|| RPMError::UnexpectedTagDataType {
                expected_data_type: "string",
                actual_data_type: entry.data.to_string(),
                tag: entry.tag.to_string(),
            })
    }

    pub fn get_entry_data_as_i18n_string(&self, tag: T) -> Result<&str, RPMError> {
        let entry = self.find_entry_or_err(tag)?;
        entry
            .data
            .as_i18n_str()
            .ok_or_else(|| RPMError::UnexpectedTagDataType {
                expected_data_type: "i18n string array",
                actual_data_type: entry.data.to_string(),
                tag: entry.tag.to_string(),
            })
    }

    pub fn get_entry_data_as_u16_array(&self, tag: T) -> Result<Vec<u16>, RPMError> {
        let entry = self.find_entry_or_err(tag)?;
        entry
            .data
            .as_u16_array()
            .ok_or_else(|| RPMError::UnexpectedTagDataType {
                expected_data_type: "uint16 array",
                actual_data_type: entry.data.to_string(),
                tag: entry.tag.to_string(),
            })
    }

    pub fn get_entry_data_as_u32(&self, tag: T) -> Result<u32, RPMError> {
        let entry = self.find_entry_or_err(tag)?;
        entry
            .data
            .as_u32()
            .ok_or_else(|| RPMError::UnexpectedTagDataType {
                expected_data_type: "uint32",
                actual_data_type: entry.data.to_string(),
                tag: entry.tag.to_string(),
            })
    }

    pub fn get_entry_data_as_u32_array(&self, tag: T) -> Result<Vec<u32>, RPMError> {
        let entry = self.find_entry_or_err(tag)?;
        entry
            .data
            .as_u32_array()
            .ok_or_else(|| RPMError::UnexpectedTagDataType {
                expected_data_type: "uint32 array",
                actual_data_type: entry.data.to_string(),
                tag: entry.tag.to_string(),
            })
    }

    pub fn get_entry_data_as_u64(&self, tag: T) -> Result<u64, RPMError> {
        let entry = self.find_entry_or_err(tag)?;
        entry
            .data
            .as_u64()
            .ok_or_else(|| RPMError::UnexpectedTagDataType {
                expected_data_type: "uint64",
                actual_data_type: entry.data.to_string(),
                tag: entry.tag.to_string(),
            })
    }

    pub fn get_entry_data_as_u64_array(&self, tag: T) -> Result<Vec<u64>, RPMError> {
        let entry = self.find_entry_or_err(tag)?;
        entry
            .data
            .as_u64_array()
            .ok_or_else(|| RPMError::UnexpectedTagDataType {
                expected_data_type: "uint64 array",
                actual_data_type: entry.data.to_string(),
                tag: entry.tag.to_string(),
            })
    }

    pub fn get_entry_data_as_string_array(&self, tag: T) -> Result<&[String], RPMError> {
        let entry = self.find_entry_or_err(tag)?;
        entry
            .data
            .as_string_array()
            .ok_or_else(|| RPMError::UnexpectedTagDataType {
                expected_data_type: "string array",
                actual_data_type: entry.data.to_string(),
                tag: entry.tag.to_string(),
            })
    }

    pub(crate) fn create_region_tag(tag: T, records_count: i32, offset: i32) -> IndexEntry<T> {
        let mut header_immutable_index_data = vec![];
        let mut hie = IndexEntry::new(tag, (records_count + 1) * -16, IndexData::Bin(Vec::new()));
        hie.num_items = 16;
        hie.write_index(&mut header_immutable_index_data)
            .expect("unable to write to memory buffer");
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
    /// Create a new full signature header.
    ///
    /// `size` is combined size of header, header store and the payload
    ///
    /// PGP and RSA tags expect signatures according to [RFC2440](https://tools.ietf.org/html/rfc2440)
    ///
    /// Please use the [`builder`](Self::builder()) which has modular and safe API.
    #[cfg(feature = "signature-meta")]
    pub(crate) fn new_signature_header(
        headers_plus_payload_size: u32,
        md5sum: &[u8],
        sha1: &str,
        rsa_spanning_header: &[u8],
        rsa_spanning_header_and_archive: &[u8],
    ) -> Self {
        SignatureHeaderBuilder::new()
            .add_digest(sha1, md5sum)
            .add_signature(rsa_spanning_header, rsa_spanning_header_and_archive)
            .build(headers_plus_payload_size)
    }

    pub fn builder() -> SignatureHeaderBuilder<Empty> {
        SignatureHeaderBuilder::<Empty>::new()
    }

    #[cfg(feature = "async-futures")]
    pub(crate) async fn parse_signature_async<I: AsyncRead + Unpin>(
        input: &mut I,
    ) -> Result<Header<IndexSignatureTag>, RPMError> {
        let result = Self::parse_async(input).await?;

        let modulo = result.index_header.header_size % 8;
        if modulo > 0 {
            let align_size = 8 - modulo;
            let mut discard = vec![0; align_size as usize];
            input.read_exact(&mut discard).await?;
        }
        Ok(result)
    }

    pub(crate) fn parse_signature<I: std::io::BufRead>(
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

    #[cfg(feature = "async-futures")]
    pub(crate) async fn write_signature_async<W: AsyncWrite + Unpin>(
        &self,
        out: &mut W,
    ) -> Result<(), RPMError> {
        self.write_async(out).await?;
        let modulo = self.index_header.header_size % 8;
        if modulo > 0 {
            let expansion = vec![0; 8 - modulo as usize];
            out.write_all(&expansion).await?;
        }
        Ok(())
    }

    // @todo: share padding code
    pub(crate) fn write_signature<W: std::io::Write>(&self, out: &mut W) -> Result<(), RPMError> {
        self.write(out)?;
        let modulo = self.index_header.header_size % 8;
        if modulo > 0 {
            let expansion = vec![0; 8 - modulo as usize];
            out.write_all(&expansion)?;
        }
        Ok(())
    }

    pub fn new_empty() -> Self {
        Self {
            index_header: IndexHeader::new(0, 0),
            index_entries: vec![],
            store: vec![],
        }
    }

    pub fn clear(&mut self) {
        self.index_entries.clear();
        self.index_header.header_size = 0;
        self.index_header.num_entries = 0;
        self.store.clear()
    }
}

/// User facing accessor type representing ownership of a file
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct FileOwnership {
    pub user: String,
    pub group: String,
}

/// Declaration what category this file belongs to
#[repr(u32)]
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, enum_primitive_derive::Primitive)]
pub enum FileCategory {
    None = 0,
    Config = constants::RPMFILE_CONFIG,
    Doc = constants::RPMFILE_DOC,
}

impl Default for FileCategory {
    fn default() -> Self {
        Self::None
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, enum_primitive_derive::Primitive)]
pub enum FileDigestAlgorithm {
    // broken and very broken
    Md5 = constants::PGPHASHALGO_MD5,
    // Sha1 = constants::PGPHASHALGO_SHA1,
    // Md2 = constants::PGPHASHALGO_MD2,

    // // not proven to be broken, weaker variants broken
    // #[allow(non_camel_case_types)]
    // Haval_5_160 = constants::PGPHASHALGO_HAVAL_5_160, // not part of PGP
    // Ripemd160 = constants::PGPHASHALGO_RIPEMD160,

    // Tiger192 = constants::PGPHASHALGO_TIGER192, // not part of PGP
    Sha2_256 = constants::PGPHASHALGO_SHA256,
    Sha2_384 = constants::PGPHASHALGO_SHA384,
    Sha2_512 = constants::PGPHASHALGO_SHA512,
    Sha2_224 = constants::PGPHASHALGO_SHA224,
}

impl Default for FileDigestAlgorithm {
    fn default() -> Self {
        // if the entry is missing, this is the default fallback
        Self::Md5
    }
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum FileDigest {
    Md5(Vec<u8>),
    Sha2_256(Vec<u8>),
    Sha2_384(Vec<u8>),
    Sha2_512(Vec<u8>),
    Sha2_224(Vec<u8>),
    // @todo unsupported other types for now
}

impl FileDigest {
    pub fn load_from_str(
        algorithm: FileDigestAlgorithm,
        stringly_data: impl AsRef<str>,
    ) -> Result<Self, RPMError> {
        let hex: Vec<u8> = hex::decode(stringly_data.as_ref())?;
        Ok(match algorithm {
            FileDigestAlgorithm::Md5 if hex.len() == 16 => FileDigest::Md5(hex),
            FileDigestAlgorithm::Sha2_256 if hex.len() == 32 => FileDigest::Sha2_256(hex),
            FileDigestAlgorithm::Sha2_224 if hex.len() == 30 => FileDigest::Sha2_224(hex),
            FileDigestAlgorithm::Sha2_384 if hex.len() == 48 => FileDigest::Sha2_384(hex),
            FileDigestAlgorithm::Sha2_512 if hex.len() == 64 => FileDigest::Sha2_512(hex),
            // @todo disambiguate mismatch of length from unsupported algorithm
            digest_algo => return Err(RPMError::UnsupportedFileDigestAlgorithm(digest_algo)),
        })
    }
}

/// User facing accessor type for a changelog entry
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct ChangelogEntry {
    pub name: String,
    pub timestamp: u64,
    pub description: String,
}

/// User facing accessor type for a file entry with contextual information
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct FileEntry {
    /// Full path of the file entry and where it will be installed to.
    pub path: PathBuf,
    /// The file mode of the file.
    pub mode: types::FileMode,
    /// Defines the owning user and group.
    pub ownership: FileOwnership,
    /// Clocks the last access time.
    pub modified_at: chrono::DateTime<chrono::Utc>,
    /// The size of this file, dirs have the inode size (which is insane)
    pub size: usize,
    /// Categorizes the file or directory into three groups.
    pub category: FileCategory,
    // @todo SELinux context? how is that done?
    pub digest: Option<FileDigest>,
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

/// A header keeping track of all other header records.
#[derive(Debug, PartialEq)]
pub(crate) struct IndexHeader {
    /// rpm specific magic header
    pub(crate) magic: [u8; 3],
    /// rpm version number, always 1
    pub(crate) version: u8,
    /// number of header entries
    pub(crate) num_entries: u32,
    /// total header size excluding the fixed part (@todo: verify this is correct)
    pub(crate) header_size: u32,
}

impl IndexHeader {
    // 16 bytes
    pub(crate) fn parse(input: &[u8]) -> Result<Self, RPMError> {
        // first three bytes are magic
        let (rest, magic) = complete::take(3usize)(input)?;
        for i in 0..2 {
            if HEADER_MAGIC[i] != magic[i] {
                return Err(RPMError::InvalidMagic {
                    expected: HEADER_MAGIC[i],
                    actual: magic[i],
                    complete_input: input.to_vec(),
                });
            }
        }
        // then version
        let (rest, version) = be_u8(rest)?;

        if version != 1 {
            return Err(RPMError::UnsupportedHeaderVersion(version));
        }
        // then reserved
        let (rest, _) = complete::take(4usize)(rest)?;
        // then number of of entries
        let (rest, num_entries) = be_u32(rest)?;
        // then size of header
        let (_rest, header_size) = be_u32(rest)?;

        Ok(IndexHeader {
            magic: HEADER_MAGIC,
            version: 1,
            num_entries,
            header_size,
        })
    }

    pub(crate) fn write<W: std::io::Write>(&self, out: &mut W) -> Result<(), RPMError> {
        out.write_all(&self.magic)?;
        out.write_all(&self.version.to_be_bytes())?;
        out.write_all(&[0; 4])?;
        out.write_all(&self.num_entries.to_be_bytes())?;
        out.write_all(&self.header_size.to_be_bytes())?;
        Ok(())
    }

    #[cfg(feature = "async-futures")]
    pub(crate) async fn write_async<W: AsyncWrite + Unpin>(
        &self,
        out: &mut W,
    ) -> Result<(), RPMError> {
        out.write_all(&self.magic).await?;
        out.write_all(&self.version.to_be_bytes()).await?;
        out.write_all(&[0; 4]).await?;
        out.write_all(&self.num_entries.to_be_bytes()).await?;
        out.write_all(&self.header_size.to_be_bytes()).await?;
        Ok(())
    }

    pub(crate) fn new(num_entries: u32, header_size: u32) -> Self {
        IndexHeader {
            magic: HEADER_MAGIC,
            version: 1,
            num_entries,
            header_size,
        }
    }
}

/// A single entry within the [`IndexHeader`](self::IndexHeader)
#[derive(Debug, PartialEq)]
pub(crate) struct IndexEntry<T: num::FromPrimitive> {
    pub(crate) tag: T,
    pub(crate) data: IndexData,
    pub(crate) offset: i32,
    pub(crate) num_items: u32,
}

impl<T: Tag> IndexEntry<T> {
    // 16 bytes
    pub(crate) fn parse(input: &[u8]) -> Result<(&[u8], Self), RPMError> {
        //first 4 bytes are the tag.
        let (input, raw_tag) = be_u32(input)?;

        let tag: T = num::FromPrimitive::from_u32(raw_tag).ok_or_else(|| RPMError::InvalidTag {
            raw_tag,
            store_type: T::tag_type_name(),
        })?;
        //next 4 bytes is the tag type
        let (input, raw_tag_type) = be_u32(input)?;

        // initialize the datatype. Parsing of the data happens later since the store comes after the index section.
        let data = IndexData::from_type_as_u32(raw_tag_type).ok_or_else(|| {
            RPMError::InvalidTagDataType {
                raw_data_type: raw_tag_type,
                store_type: T::tag_type_name(),
            }
        })?;

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

    #[cfg(feature = "async-futures")]
    pub(crate) async fn write_index_async<W: AsyncWrite + Unpin>(
        &self,
        out: &mut W,
    ) -> Result<(), RPMError> {
        // unwrap() is safe because tags are predefined and are all within u32 range.
        let mut written = out.write(&self.tag.to_u32().unwrap().to_be_bytes()).await?;
        written += out.write(&self.data.type_as_u32().to_be_bytes()).await?;
        written += out.write(&self.offset.to_be_bytes()).await?;
        written += out.write(&self.num_items.to_be_bytes()).await?;
        assert_eq!(16, written, "there should be 16 bytes written");
        Ok(())
    }

    pub(crate) fn write_index<W: std::io::Write>(&self, out: &mut W) -> Result<(), RPMError> {
        // unwrap() is safe because tags are predefined.
        let mut written = out.write(&self.tag.to_u32().unwrap().to_be_bytes())?;
        written += out.write(&self.data.type_as_u32().to_be_bytes())?;
        written += out.write(&self.offset.to_be_bytes())?;
        written += out.write(&self.num_items.to_be_bytes())?;
        assert_eq!(16, written, "there should be 16 bytes written");
        Ok(())
    }

    pub(crate) fn new(tag: T, offset: i32, data: IndexData) -> IndexEntry<T> {
        IndexEntry {
            tag,
            offset,
            num_items: data.num_items(),
            data,
        }
    }
}

/// Data as present in a [`IndexEntry`](self::IndexEntry) .
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum IndexData {
    Null,
    Char(Vec<u8>),
    Int8(Vec<u8>),
    Int16(Vec<u16>),
    Int32(Vec<u32>),
    Int64(Vec<u64>),
    StringTag(String),
    Bin(Vec<u8>),
    StringArray(Vec<String>),
    I18NString(Vec<String>),
}

impl fmt::Display for IndexData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
    pub(crate) fn append(&self, store: &mut Vec<u8>) -> u32 {
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
                store.extend_from_slice(d);
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

    pub(crate) fn num_items(&self) -> u32 {
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

    pub(crate) fn from_type_as_u32(i: u32) -> Option<Self> {
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

    pub(crate) fn type_as_u32(&self) -> u32 {
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

    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            IndexData::StringTag(s) => Some(s),
            _ => None,
        }
    }

    #[allow(unused)]
    pub(crate) fn as_char_array(&self) -> Option<Vec<u8>> {
        match self {
            IndexData::Char(s) => Some(s.to_vec()),
            _ => None,
        }
    }

    #[allow(unused)]
    pub(crate) fn as_u8_array(&self) -> Option<Vec<u8>> {
        match self {
            IndexData::Int8(s) => Some(s.to_vec()),
            _ => None,
        }
    }

    pub(crate) fn as_u16_array(&self) -> Option<Vec<u16>> {
        match self {
            IndexData::Int16(s) => Some(s.to_vec()),
            _ => None,
        }
    }

    pub(crate) fn as_u32(&self) -> Option<u32> {
        match self {
            IndexData::Int32(s) => s.first().copied(),
            _ => None,
        }
    }
    pub(crate) fn as_u32_array(&self) -> Option<Vec<u32>> {
        match self {
            IndexData::Int32(s) => Some(s.to_vec()),
            _ => None,
        }
    }

    pub(crate) fn as_u64(&self) -> Option<u64> {
        match self {
            IndexData::Int64(s) => s.first().copied(),
            _ => None,
        }
    }

    pub(crate) fn as_u64_array(&self) -> Option<Vec<u64>> {
        match self {
            IndexData::Int64(s) => Some(s.to_vec()),
            _ => None,
        }
    }

    pub(crate) fn as_string_array(&self) -> Option<&[String]> {
        match self {
            IndexData::StringArray(d) | IndexData::I18NString(d) => Some(d),
            _ => None,
        }
    }

    pub(crate) fn as_i18n_str(&self) -> Option<&str> {
        match self {
            IndexData::I18NString(s) => {
                // @todo: an actual implementation that doesn't just get the first string from the table
                Some(&s[0])
            }
            _ => None,
        }
    }

    pub(crate) fn as_binary(&self) -> Option<&[u8]> {
        match self {
            IndexData::Bin(d) => Some(d.as_slice()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_region_tag() -> Result<(), Box<dyn std::error::Error>> {
        let region_entry = Header::create_region_tag(IndexSignatureTag::HEADER_SIGNATURES, 2, 400);

        let possible_binary = region_entry.data.as_binary();

        assert!(possible_binary.is_some(), "should be binary");

        let data = possible_binary.unwrap();

        let (_, entry) = IndexEntry::<IndexSignatureTag>::parse(data)?;

        assert_eq!(entry.tag, IndexSignatureTag::HEADER_SIGNATURES);
        assert_eq!(
            entry.data.type_as_u32(),
            IndexData::Bin(Vec::new()).type_as_u32()
        );
        assert_eq!(-48, entry.offset);

        Ok(())
    }

    #[cfg(feature = "signature-meta")]
    #[test]
    fn signature_header_build() {
        let size: u32 = 209_348;
        let md5sum: &[u8] = &[22u8; 16];
        let sha1 = "5A884F0CB41EC3DA6D6E7FC2F6AB9DECA8826E8D";
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
                    IndexData::StringTag(sha1.to_owned()),
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
            sha1,
            rsa_spanning_header,
            rsa_spanning_header_and_archive,
        );

        assert_eq!(built, truth);
    }
}
