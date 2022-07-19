use std::io;

use thiserror::Error;

use crate::FileDigestAlgorithm;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum RPMError {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    Hex(#[from] hex::FromHexError),

    #[error("{0}")]
    Nom(String),
    #[error(
        "invalid magic expected: {expected} but got: {actual} - whole input was {complete_input:?}"
    )]
    InvalidMagic {
        expected: u8,
        actual: u8,
        complete_input: Vec<u8>,
    },
    #[error("unsupported Version {0} - only header version 1 is supported")]
    UnsupportedHeaderVersion(u8),
    #[error("invalid tag {raw_tag} for store {store_type}")]
    InvalidTag {
        raw_tag: u32,
        store_type: &'static str,
    },
    #[error("invalid tag data type in store {store_type}: expected 0 - 9 but got {raw_data_type}")]
    InvalidTagDataType {
        raw_data_type: u32,
        store_type: &'static str,
    },
    #[error("unable to find tag {0}")]
    TagNotFound(String),
    #[error("tag {tag} has data type {actual_data_type}, not {expected_data_type}")]
    UnexpectedTagDataType {
        expected_data_type: &'static str,
        actual_data_type: String,
        tag: String,
    },
    #[error("invalid tag array index {tag} with {index} while bounded at {bound}")]
    InvalidTagIndex { tag: String, index: u32, bound: u32 },

    #[error("invalid tag value enum varaint for {tag} with {variant}")]
    InvalidTagValueEnumVariant { tag: String, variant: u32 },

    #[error("unsupported lead major version {0} - only version 3 is supported")]
    InvalidLeadMajorVersion(u8),

    #[error("unsupported lead major version {0} - only version 0 is supported")]
    InvalidLeadMinorVersion(u8),

    #[error("invalid type - expected 0 or 1 but got {0}")]
    InvalidLeadPKGType(u16),

    #[error("invalid os-type - expected 1 but got {0}")]
    InvalidLeadOSType(u16),

    #[error("invalid signature-type - expected 5 but got {0}")]
    InvalidLeadSignatureType(u16),

    #[error("invalid size of reserved area - expected length of {expected} but got {actual}")]
    InvalidReservedSpaceSize { expected: u16, actual: usize },

    #[error("invalid destination path {path} - {desc}")]
    InvalidDestinationPath { path: String, desc: &'static str },

    #[error("signature packet not found in what is supposed to be a signature")]
    NoSignatureFound,

    #[error("error creating signature: {0}")]
    SignError(Box<dyn std::error::Error>),

    #[error("error parsing key - {details}. underlying error was: {source}")]
    KeyLoadError {
        source: Box<dyn std::error::Error>,
        details: &'static str,
    },

    #[error("error verifying signature with key {key_ref}: {source}")]
    VerificationError {
        source: Box<dyn std::error::Error>,
        key_ref: String,
    },

    #[error("unable to find key with key-ref: {key_ref}")]
    KeyNotFoundError { key_ref: String },

    #[error("unknown compressor type {0} - only gzip and none are supported")]
    UnknownCompressorType(String),

    #[error("unsupported file digest algorithm {0:?}")]
    UnsupportedFileDigestAlgorithm(FileDigestAlgorithm),

    #[error("invalid file mode {raw_mode} - {reason}")]
    InvalidFileMode { raw_mode: i32, reason: &'static str },
}

impl From<nom::Err<(&[u8], nom::error::ErrorKind)>> for RPMError {
    fn from(error: nom::Err<(&[u8], nom::error::ErrorKind)>) -> Self {
        match error {
            nom::Err::Error((_, kind)) | nom::Err::Failure((_, kind)) => {
                RPMError::Nom(kind.description().to_string())
            }
            nom::Err::Incomplete(_) => RPMError::Nom("unhandled incomplete".to_string()),
        }
    }
}
