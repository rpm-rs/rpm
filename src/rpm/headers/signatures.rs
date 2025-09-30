//! signature index construction as builder pattern

use super::*;

use crate::constants::*;
#[cfg(feature = "signature-pgp")]
use crate::signature::pgp::Verifier;

#[cfg(feature = "signature-pgp")]
use pgp::crypto::public_key::PublicKeyAlgorithm;
#[cfg(feature = "signature-pgp")]
use pgp::{base64::Base64Decoder, base64::Base64Reader};

use std::default::Default;

/// base signature header builder
pub struct SignatureHeaderBuilder {
    openpgp_signatures: Vec<Vec<u8>>,
    header_sha256: Option<String>,
    header_sha3_256: Option<String>,
    content_length: Option<u64>,
}

impl Default for SignatureHeaderBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "signature-pgp")]
pub(crate) fn decode_sig(signature: &str) -> Result<Vec<u8>, crate::Error> {
    use std::io::Read;

    let mut decoded_sig = Vec::new();
    let mut decoder = Base64Decoder::new(Base64Reader::new(signature.as_ref()));
    decoder.read_to_end(&mut decoded_sig)?;
    Ok(decoded_sig)
}

#[cfg(feature = "signature-pgp")]
pub(crate) fn encode_sig(signature: &[u8]) -> String {
    use base64::prelude::*;
    BASE64_STANDARD.encode(signature)
}

impl SignatureHeaderBuilder {
    pub fn new() -> Self {
        Self {
            openpgp_signatures: Vec::new(),
            header_sha256: None,
            header_sha3_256: None,
            content_length: None,
        }
    }

    /// Construct the complete signature header.
    pub fn build(self) -> Result<Header<IndexSignatureTag>, crate::Error> {
        let mut entries = Vec::new();

        #[cfg(feature = "signature-pgp")]
        if !self.openpgp_signatures.is_empty() {
            let mut openpgp_signatures = Vec::new();
            let mut legacy_sig = None;

            // need to base64-encode the raw bytes of the signatures
            for sig_bytes in &self.openpgp_signatures {
                let signature = Verifier::parse_signature(sig_bytes)?;
                let tag = match signature
                    .config()
                    .ok_or(crate::Error::UnknownVersionSignature)?
                    .pub_alg
                {
                    PublicKeyAlgorithm::RSA => IndexSignatureTag::RPMSIGTAG_RSA,
                    PublicKeyAlgorithm::ECDSA
                    | PublicKeyAlgorithm::EdDSALegacy
                    | PublicKeyAlgorithm::Ed25519 => IndexSignatureTag::RPMSIGTAG_DSA,
                    a => return Err(crate::Error::UnsupportedPGPKeyType(a)),
                };
                legacy_sig = Some((tag, sig_bytes));
                openpgp_signatures.push(encode_sig(sig_bytes));
            }

            entries.push(IndexEntry::new(
                IndexSignatureTag::RPMSIGTAG_OPENPGP,
                0i32,
                IndexData::StringArray(openpgp_signatures),
            ));

            // the legacy signature tags are produced from the last signature in the list
            if let Some((tag, sig_bytes)) = legacy_sig {
                entries.push(IndexEntry::new(
                    tag,
                    0i32,
                    IndexData::Bin(sig_bytes.clone()),
                ));
            }
        }

        if let Some(digest) = self.header_sha256 {
            entries.push(IndexEntry::new(
                IndexSignatureTag::RPMSIGTAG_SHA256,
                0i32,
                IndexData::StringTag(digest),
            ));
        }

        if let Some(digest) = self.header_sha3_256 {
            entries.push(IndexEntry::new(
                IndexSignatureTag::RPMSIGTAG_SHA3_256,
                0i32,
                IndexData::StringTag(digest),
            ));
        }

        if let Some(len) = self.content_length {
            if let Ok(len) = u32::try_from(len) {
                entries.push(IndexEntry::new(
                    IndexSignatureTag::RPMSIGTAG_SIZE,
                    0,
                    IndexData::Int32(vec![len]),
                ));
            } else {
                entries.push(IndexEntry::new(
                    IndexSignatureTag::RPMSIGTAG_LONGSIZE,
                    0,
                    IndexData::Int64(vec![len]),
                ));
            }
        }

        let header = Header::<IndexSignatureTag>::from_entries(
            entries,
            IndexSignatureTag::HEADER_SIGNATURES,
        );

        Ok(header)
    }

    /// Add a sha256 digest of the header bytes
    pub fn set_sha256_digest(mut self, digest_header_sha256: &str) -> Self {
        self.header_sha256 = Some(digest_header_sha256.to_owned());
        self
    }

    /// Add a sha3-256 digest of the header bytes
    pub fn set_sha3_256_digest(mut self, digest_header_sha3_256: &str) -> Self {
        self.header_sha3_256 = Some(digest_header_sha3_256.to_owned());
        self
    }

    /// Set the content length (compressed payload + header size).
    pub fn set_content_length(mut self, length: u64) -> Self {
        self.content_length = Some(length);
        self
    }

    // Add an openpgp signature of the header bytes
    pub fn add_openpgp_signature(mut self, signature: Vec<u8>) -> Self {
        self.openpgp_signatures.push(signature);
        self
    }

    // Clear all header signatures
    pub fn clear_signatures(mut self) -> Self {
        self.openpgp_signatures.clear();
        self
    }
}
