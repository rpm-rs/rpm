use std::{io, str::Utf8Error};

use thiserror::Error;

use crate::{DigestAlgorithm, TimestampError};

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
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

    #[error("invalid tag value enum variant for {tag} with {variant}")]
    InvalidTagValueEnumVariant { tag: String, variant: u32 },

    #[error("invalid size of reserved area - expected length of {expected} but got {actual}")]
    InvalidReservedSpaceSize { expected: u16, actual: usize },

    #[error("invalid destination path {path} - {desc}")]
    InvalidDestinationPath { path: String, desc: &'static str },

    #[error("invalid capabilities specified {caps}")]
    InvalidCapabilities { caps: String },

    #[error("signature packet not found in what is supposed to be a signature")]
    NoSignatureFound,

    #[cfg(feature = "signature-pgp")]
    #[error("error creating signature: {0}")]
    SignError(#[source] pgp::errors::Error),

    #[error("error parsing keys, failed to parse bytes as utf8 for ascii armored parsing")]
    KeyLoadUtf8Error(
        #[from]
        #[source]
        Utf8Error,
    ),

    #[cfg(feature = "signature-pgp")]
    #[error("errors parsing keys, failed to parse bytes as ascii armored key")]
    KeyLoadSecretKeyError(
        #[from]
        #[source]
        pgp::errors::Error,
    ),

    #[cfg(feature = "signature-pgp")]
    #[error("error verifying signature with key {key_ref}: {source}")]
    VerificationError {
        #[source]
        source: pgp::errors::Error,
        key_ref: String,
    },

    #[error("digests from content did not match those in the header")]
    DigestMismatchError,

    #[error("unable to find key with key-ref: {key_ref}")]
    KeyNotFoundError { key_ref: String },

    #[error("unknown compressor type {0} - only gzip and none are supported")]
    UnknownCompressorType(String),

    #[error("unsupported digest algorithm {0:?}")]
    UnsupportedDigestAlgorithm(DigestAlgorithm),

    #[cfg(feature = "signature-pgp")]
    #[error("unsupported PGP key type {0:?}")]
    UnsupportedPGPKeyType(pgp::crypto::public_key::PublicKeyAlgorithm),

    #[error("invalid file mode {raw_mode} - {reason}")]
    InvalidFileMode { raw_mode: i32, reason: &'static str },

    #[error("timestamp conversion error: {0:?}")]
    TimestampConv(TimestampError),

    #[error("{0}")]
    InvalidFileCaps(String),
}

impl From<nom::Err<(&[u8], nom::error::ErrorKind)>> for Error {
    fn from(error: nom::Err<(&[u8], nom::error::ErrorKind)>) -> Self {
        match error {
            nom::Err::Error((_, kind)) | nom::Err::Failure((_, kind)) => {
                Error::Nom(kind.description().to_string())
            }
            nom::Err::Incomplete(_) => Error::Nom("unhandled incomplete".to_string()),
        }
    }
}

impl From<TimestampError> for Error {
    fn from(error: TimestampError) -> Self {
        Error::TimestampConv(error)
    }
}

// Assert at compile-time that Error implements Send and Sync.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Error>();
};
