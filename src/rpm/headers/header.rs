use nom::bytes::complete;
use nom::number::complete::{be_i16, be_i32, be_i64, be_i8, be_u32, be_u8};

use crate::constants::{self,*};
use std::convert::TryInto;
use std::fmt;
use std::path::PathBuf;
use chrono::offset::TimeZone;
use num_traits::FromPrimitive;

use super::*;
use crate::errors::*;

/// Header tag.
///
/// Each and every header has a particular header tag that identifies the type of
/// the header the format / information contained in that header.
pub trait Tag:
    num::FromPrimitive + num::ToPrimitive + PartialEq + fmt::Display + fmt::Debug + Copy + TypeName
{
}

impl<T> Tag for T where
    T: num::FromPrimitive
        + num::ToPrimitive
        + PartialEq
        + fmt::Display
        + fmt::Debug
        + Copy
        + TypeName
{
}

#[derive(Debug, PartialEq)]
pub struct Header<T: num::FromPrimitive> {
    pub(crate) index_header: IndexHeader,
    pub(crate) index_entries: Vec<IndexEntry<T>>,
    pub(crate) store: Vec<u8>,
}

impl<T> Header<T>
where
    T: Tag,
{
    pub(crate) fn parse<I: std::io::BufRead>(input: &mut I) -> Result<Header<T>, RPMError> {
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

    pub(crate) fn write<W: std::io::Write>(&self, out: &mut W) -> Result<(), RPMError> {
        self.index_header.write(out)?;
        for entry in &self.index_entries {
            entry.write_index(out)?;
        }
        out.write_all(&self.store)?;
        Ok(())
    }

    pub(crate) fn find_entry_or_err(&self, tag: &T) -> Result<&IndexEntry<T>, RPMError> {
        self.index_entries
            .iter()
            .find(|entry| &entry.tag == tag)
            .ok_or_else(|| RPMError::TagNotFound(tag.to_string()))
    }

    pub(crate) fn get_entry_binary_data(&self, tag: T) -> Result<&[u8], RPMError> {
        let entry = self.find_entry_or_err(&tag)?;
        entry
            .data
            .as_binary()
            .ok_or_else(|| RPMError::UnexpectedTagDataType {
                expected_data_type: "binary",
                actual_data_type: entry.data.to_string(),
                tag: entry.tag.to_string(),
            })
    }

    pub(crate) fn get_entry_string_data(&self, tag: T) -> Result<&str, RPMError> {
        let entry = self.find_entry_or_err(&tag)?;
        entry
            .data
            .as_str()
            .ok_or_else(|| RPMError::UnexpectedTagDataType {
                expected_data_type: "string",
                actual_data_type: entry.data.to_string(),
                tag: entry.tag.to_string(),
            })
    }


    pub(crate) fn get_entry_i16_array_data(&self, tag: T) -> Result<Vec<i16>, RPMError> {
        let entry = self.find_entry_or_err(&tag)?;
        entry
            .data
            .as_i16_array()
            .ok_or_else(|| RPMError::UnexpectedTagDataType {
                expected_data_type: "i64 array",
                actual_data_type: entry.data.to_string(),
                tag: entry.tag.to_string(),
            })
    }

    pub(crate) fn get_entry_i32_data(&self, tag: T) -> Result<i32, RPMError> {
        let entry = self.find_entry_or_err(&tag)?;
        entry
            .data
            .as_i32()
            .ok_or_else(|| RPMError::UnexpectedTagDataType {
                expected_data_type: "i32",
                actual_data_type: entry.data.to_string(),
                tag: entry.tag.to_string(),
            })
    }

    pub(crate) fn get_entry_i32_array_data(&self, tag: T) -> Result<Vec<i32>, RPMError> {
        let entry = self.find_entry_or_err(&tag)?;
        entry
            .data
            .as_i32_array()
            .ok_or_else(|| RPMError::UnexpectedTagDataType {
                expected_data_type: "i32 array",
                actual_data_type: entry.data.to_string(),
                tag: entry.tag.to_string(),
            })
    }

    pub(crate) fn get_entry_i64_data(&self, tag: T) -> Result<i64, RPMError> {
        let entry = self.find_entry_or_err(&tag)?;
        entry
            .data
            .as_i64()
            .ok_or_else(|| RPMError::UnexpectedTagDataType {
                expected_data_type: "i64",
                actual_data_type: entry.data.to_string(),
                tag: entry.tag.to_string(),
            })
    }

    pub(crate) fn get_entry_i64_array_data(&self, tag: T) -> Result<Vec<i64>, RPMError> {
        let entry = self.find_entry_or_err(&tag)?;
        entry
            .data
            .as_i64_array()
            .ok_or_else(|| RPMError::UnexpectedTagDataType {
                expected_data_type: "i64 array",
                actual_data_type: entry.data.to_string(),
                tag: entry.tag.to_string(),
            })
    }

    pub(crate) fn get_entry_string_array_data(&self, tag: T) -> Result<&[String], RPMError> {
        let entry = self.find_entry_or_err(&tag)?;
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
    /// Create a new full signature header.
    ///
    /// `size` is combined size of header, header store and the payload
    ///
    /// PGP and RSA tags expect signatures according to [RFC2440](https://tools.ietf.org/html/rfc2440)
    ///
    /// Please use the [`builder`](Self::builder()) which has modular and safe API.
    pub(crate) fn new_signature_header(
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

    pub(crate) fn write_signature<W: std::io::Write>(&self, out: &mut W) -> Result<(), RPMError> {
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
    #[inline]
    pub fn get_payload_format(&self) -> Result<&str, RPMError> {
        self.get_entry_string_data(IndexTag::RPMTAG_PAYLOADFORMAT)
    }

    #[inline]
    pub fn get_payload_compressor(&self) -> Result<&str, RPMError> {
        self.get_entry_string_data(IndexTag::RPMTAG_PAYLOADCOMPRESSOR)
    }

    #[inline]
    pub fn get_file_checksums(&self) -> Result<&[String], RPMError> {
        self.get_entry_string_array_data(IndexTag::RPMTAG_FILEDIGESTS)
    }

    #[inline]
    pub fn get_name(&self) -> Result<&str, RPMError> {
        self.get_entry_string_data(IndexTag::RPMTAG_NAME)
    }

    #[inline]
    pub fn get_epoch(&self) -> Result<i32, RPMError> {
        self.get_entry_i32_data(IndexTag::RPMTAG_EPOCH)
    }

    #[inline]
    pub fn get_version(&self) -> Result<&str, RPMError> {
        self.get_entry_string_data(IndexTag::RPMTAG_VERSION)
    }

    #[inline]
    pub fn get_release(&self) -> Result<&str, RPMError> {
        self.get_entry_string_data(IndexTag::RPMTAG_RELEASE)
    }

    #[inline]
    pub fn get_arch(&self) -> Result<&str, RPMError> {
        self.get_entry_string_data(IndexTag::RPMTAG_ARCH)
    }

    #[inline]
    pub fn get_install_time(&self) -> Result<i64, RPMError> {
        self.get_entry_i64_data(IndexTag::RPMTAG_INSTALLTIME)
    }

    /// Extract a the set of contained file names.
    pub fn get_file_paths(&self) -> Result<Vec<PathBuf>, RPMError> {
        // reconstruct the messy de-constructed paths
        let base = self.get_entry_string_array_data(IndexTag::RPMTAG_BASENAMES)?;
        let biject = self.get_entry_i32_array_data(IndexTag::RPMTAG_DIRINDEXES)?;
        let dirs = self.get_entry_string_array_data(IndexTag::RPMTAG_DIRNAMES)?;

        let n = dirs.len();
        let v = base
            .into_iter()
            .zip(biject.into_iter())
            .try_fold::<Vec<PathBuf>, _, _>(
                Vec::<PathBuf>::with_capacity(base.len()),
                |mut acc, item| {
                    let (base, dir_index) = item;
                    if let Some(dir) = dirs.get(dir_index as usize) {
                        acc.push(PathBuf::from(dir).join(base));
                        Ok(acc)
                    } else {
                        Err(RPMError::InvalidTagIndex {
                            tag: IndexTag::RPMTAG_DIRINDEXES.to_string(),
                            index: dir_index as u32,
                            bound: n as u32,
                        })
                    }
                },
            )?;
        Ok(v)
    }

    /// The digest algorithm used per file.
    ///
    /// Note that this is not necessarily the same as the digest
    /// used for headers.
    pub fn get_file_digest_algorithm(&self) -> Result<FileDigestAlgorithm, RPMError> {
        self.get_entry_i32_data(IndexTag::RPMTAG_FILEDIGESTALGO)
            .and_then(|x| FileDigestAlgorithm::from_i32(x).ok_or_else (|| RPMError::InvalidTagValueEnumVariant {
                tag: IndexTag::RPMTAG_FILEDIGESTALGO.to_string(),
                variant: x as u32,
            }))
    }


    /// Extract a the set of contained file names including the additional metadata.
    pub fn get_file_entries(&self) -> Result<Vec<FileEntry>, RPMError> {
        // rpm does not encode it, if it is the default md5
        let algorithm = self.get_file_digest_algorithm().unwrap_or_default();
        //
        let modes = self.get_entry_i16_array_data(IndexTag::RPMTAG_FILEMODES)?;
        let users = self.get_entry_string_array_data(IndexTag::RPMTAG_FILEUSERNAME)?;
        let groups = self.get_entry_string_array_data(IndexTag::RPMTAG_FILEGROUPNAME)?;
        let digests = self.get_entry_string_array_data(IndexTag::RPMTAG_FILEDIGESTS)?;
        let mtimes = self.get_entry_i32_array_data(IndexTag::RPMTAG_FILEMTIMES)?;
        let sizes = self.get_entry_i64_array_data(IndexTag::RPMTAG_LONGFILESIZES).or_else(|_e| {
            self.get_entry_i32_array_data(IndexTag::RPMTAG_FILESIZES).map(|file_sizes| {
                file_sizes.into_iter().map(|file_size| file_size as _ ).collect::<Vec<i64>>()
            })
        })?;
        let flags = self.get_entry_i32_array_data(IndexTag::RPMTAG_FILEFLAGS)?;
        // @todo
        // let caps = self.get_entry_i32_array_data(IndexTag::RPMTAG_FILECAPS)?;


        let paths = self.get_file_paths()?;
        let n = paths.len();

        let v = itertools::multizip((paths.into_iter(), users, groups, modes, digests, mtimes, sizes, flags))
            .try_fold::<Vec<FileEntry>,_,Result<_, RPMError>>(
                Vec::with_capacity(n),
                |mut acc, (path,user,group,mode, digest,mtime, size, flags)| {
                    let digest = if digest.is_empty() { None } else { Some(FileDigest::load_from_str(algorithm, digest)?) };
                    let utc = chrono::Utc;
                    acc.push(FileEntry {
                        path,
                        ownership: FileOwnership{
                            user: user.to_owned(),
                            group: group.to_owned(),
                        },
                        mode: FileMode(mode as u16),
                        modified_at: utc.timestamp( mtime as i64, 0u32),
                        digest,
                        category: FileCategory::from_i32(flags).unwrap_or_default(),
                        size: size as usize,
                    });
                    Ok(acc)
                })?;
        Ok(v)
    }
}


/// User facing accessor type representing a file mode
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct FileMode(pub u16);

/// User facing accessor type representing ownership of a file
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct FileOwnership{ user: String, group: String}



/// Declaration what category this file belongs to
/// @todo must be bitflags
#[derive(Debug,Clone,Copy,Hash,Eq,PartialEq,enum_primitive_derive::Primitive)]
#[repr(i32)]
pub enum FileCategory {
    None = 0i32,
    Config = constants::RPMFILE_CONFIG,
    Doc = constants::RPMFILE_DOC,
}

impl Default for FileCategory {
    fn default() -> Self {
        Self::None
    }
}



#[repr(i32)]
#[derive(Debug,Clone,Copy,enum_primitive_derive::Primitive)]
pub enum FileDigestAlgorithm {
    // broken and very broken
    Md5 = constants::PGPHASHALGO_MD5,
    Sha1 = constants::PGPHASHALGO_SHA1,
    Md2 = constants::PGPHASHALGO_MD2,

    // not proven to be broken, weaker variants broken
    #[allow(non_camel_case_types)]
    Haval_5_160 = constants::PGPHASHALGO_HAVAL_5_160, // not part of PGP
    Ripemd160 = constants::PGPHASHALGO_RIPEMD160,

    Tiger192 = constants::PGPHASHALGO_TIGER192, // not part of PGP
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
    pub fn load_from_str(algorithm: FileDigestAlgorithm, stringly_data: impl AsRef<str>) -> Result<Self, RPMError> {
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

/// User facing accessor type for a file entry with contextual information
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct FileEntry {
    /// Full path of the file entry and where it will be installed to.
    pub path: PathBuf,
    /// The file mode of the file.
    pub mode: FileMode,
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

#[cfg(test)]
mod tests2 {
    use super::*;

    #[test]
    fn signature_header_build() {
        let size: i32 = 209_348;
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
            sha1,
            rsa_spanning_header,
            rsa_spanning_header_and_archive,
        );

        assert_eq!(built, truth);
    }
}

/// A header keeping track of all other headerr records.
#[derive(Debug, PartialEq)]
pub(crate) struct IndexHeader {
    /// rpm specific magic header
    pub(crate) magic: [u8; 3],
    /// rpm version number, always 1
    pub(crate) version: u8,
    /// number of header entries
    pub(crate) num_entries: u32,
    /// total header size excluding the fixed part ( I think )
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
            magic: magic.try_into().unwrap(),
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

    pub(crate) fn new(num_entries: u32, header_size: u32) -> Self {
        IndexHeader {
            magic: HEADER_MAGIC,
            version: 1,
            num_entries,
            header_size,
        }
    }
}

/// A singel entry within the [`IndexHeader`](self::IndexHeader)
#[derive(Debug, PartialEq)]
pub(crate) struct IndexEntry<T: num::FromPrimitive> {
    pub(crate) tag: T,
    pub(crate) data: IndexData,
    pub(crate) offset: i32,
    pub(crate) num_items: u32,
}

use crate::constants::TypeName;

impl<T: num::FromPrimitive + num::ToPrimitive + fmt::Debug + TypeName> IndexEntry<T> {
    // 16 bytes
    pub(crate) fn parse(input: &[u8]) -> Result<(&[u8], Self), RPMError> {
        //first 4 bytes are the tag.
        let (input, raw_tag) = be_u32(input)?;

        let tag: T = num::FromPrimitive::from_u32(raw_tag).ok_or_else(|| RPMError::InvalidTag {
            raw_tag: raw_tag,
            store_type: T::type_name(),
        })?;
        //next 4 bytes is the tag type
        let (input, raw_tag_type) = be_u32(input)?;

        // initialize the datatype. Parsing of the data happens later since the store comes after the index section.
        let data =
            IndexData::from_u32(raw_tag_type).ok_or_else(|| RPMError::InvalidTagDataType {
                raw_data_type: raw_tag_type,
                store_type: T::type_name(),
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

    pub(crate) fn write_index<W: std::io::Write>(&self, out: &mut W) -> Result<(), RPMError> {
        let mut written = out.write(&self.tag.to_u32().unwrap().to_be_bytes())?;
        written += out.write(&self.data.to_u32().to_be_bytes())?;
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
    Int8(Vec<i8>),
    Int16(Vec<i16>),
    Int32(Vec<i32>),
    Int64(Vec<i64>),
    StringTag(String),
    Bin(Vec<u8>),
    StringArray(Vec<String>),
    I18NString(Vec<String>),
}

impl fmt::Display for IndexData {
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
    pub(crate) fn from_u32(i: u32) -> Option<Self> {
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
    pub(crate) fn to_u32(&self) -> u32 {
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
            IndexData::StringTag(s) => Some(&s),
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
    pub(crate) fn as_i8_array(&self) -> Option<Vec<i8>> {
        match self {
            IndexData::Int8(s) => Some(s.to_vec()),
            _ => None,
        }
    }

    pub(crate) fn as_i16_array(&self) -> Option<Vec<i16>> {
        match self {
            IndexData::Int16(s) => Some(s.to_vec()),
            _ => None,
        }
    }


    pub(crate) fn as_i32(&self) -> Option<i32> {
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
    pub(crate) fn as_i32_array(&self) -> Option<Vec<i32>> {
        match self {
            IndexData::Int32(s) => Some(s.to_vec()),
            _ => None,
        }
    }

    pub(crate) fn as_i64(&self) -> Option<i64> {
        match self {
            IndexData::Int64(s) => {
                if !s.is_empty() {
                    Some(s[0])
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub(crate) fn as_i64_array(&self) -> Option<Vec<i64>> {
        match self {
            IndexData::Int64(s) => Some(s.to_vec()),
            _ => None,
        }
    }

    pub(crate) fn as_string_array(&self) -> Option<&[String]> {
        match self {
            IndexData::StringArray(d) | IndexData::I18NString(d) => Some(&d),
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
