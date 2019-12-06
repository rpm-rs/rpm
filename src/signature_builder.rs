//! signature index construction as builder pattern

use super::*;

use std::default::Default;

// marker trait for stages
pub trait ConstructionStage {}

pub struct Empty;
pub struct WithDigest;
pub struct WithSignature;

impl ConstructionStage for Empty {}

impl ConstructionStage for WithDigest {}

impl ConstructionStage for WithSignature {}

/// base signature header builder
///
/// T describes the stage and can be one of Empty, WithDigest, WithSignature
pub struct SignatureHeaderBuilder<T>
where
    T: ConstructionStage,
{
    entries: Vec<IndexEntry<IndexSignatureTag>>,
    // TODO right now this is always 0
    // TODO verify what this actually is
    // TODO and how it must be constructed
    offset: i32,
    phantom: std::marker::PhantomData<T>,
}

impl SignatureHeaderBuilder<Empty> {
    pub fn new() -> Self {
        Self {
            entries: Vec::with_capacity(10),
            offset: 0i32,
            phantom: Default::default(),
        }
    }
    pub fn with_offset(offset: i32) -> Self {
        Self {
            entries: Vec::with_capacity(10),
            offset,
            phantom: Default::default(),
        }
    }
}

impl<T> SignatureHeaderBuilder<T>
where
    T: ConstructionStage,
{
    pub fn build(mut self, signature_size: i32) -> Header<IndexSignatureTag> {
        self.entries.insert(
            0,
            IndexEntry::new(
                IndexSignatureTag::RPMSIGTAG_SIZE,
                self.offset,
                IndexData::Int32(vec![signature_size]),
            ),
        );

        Header::<IndexSignatureTag>::from_entries(
            self.entries,
            IndexSignatureTag::HEADER_SIGNATURES,
        )
    }
}

impl SignatureHeaderBuilder<Empty> {
    /// add a digest over the header and a signature accross header and source excluding the static lead
    pub fn add_digest(
        mut self,
        digest_header_only: &str,
        digest_header_and_archive: &[u8],
    ) -> SignatureHeaderBuilder<WithDigest> {
        self.entries.push(IndexEntry::new(
            IndexSignatureTag::RPMSIGTAG_SHA1,
            self.offset,
            IndexData::StringTag(digest_header_only.to_string()),
        ));
        self.entries.push(IndexEntry::new(
            IndexSignatureTag::RPMSIGTAG_MD5,
            self.offset,
            IndexData::Bin(digest_header_and_archive.to_vec()),
        ));
        SignatureHeaderBuilder::<WithDigest> {
            entries: self.entries,
            offset: self.offset,
            phantom: Default::default(),
        }
    }
}

impl SignatureHeaderBuilder<WithDigest> {
    /// add a signature over the header and a signature accross header and source excluding the static lead
    pub fn add_signature(
        mut self,
        rsa_sig_header_only: &[u8],
        rsa_sig_header_and_archive: &[u8],
    ) -> SignatureHeaderBuilder<WithSignature> {
        self.entries.push(IndexEntry::new(
            IndexSignatureTag::RPMSIGTAG_RSA,
            self.offset,
            IndexData::Bin(rsa_sig_header_only.to_vec()),
        ));
        self.entries.push(IndexEntry::new(
            IndexSignatureTag::RPMSIGTAG_PGP,
            self.offset,
            IndexData::Bin(rsa_sig_header_and_archive.to_vec()),
        ));
        SignatureHeaderBuilder::<WithSignature> {
            entries: self.entries,
            offset: self.offset,
            phantom: Default::default(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn signature_builder() {
        let builder = SignatureHeaderBuilder::<Empty>::new();

        let rsa_sig_header_only = [0u8; 32];
        let rsa_sig_header_and_archive = [0u8; 32];
        let _digest_header_only = [0u8; 64];
        let digest_header_and_archive = [0u8; 64];

        let _header = builder
            .add_digest("", &digest_header_and_archive[..])
            .add_signature(&rsa_sig_header_only[..], &rsa_sig_header_and_archive[..])
            .build(32i32);
    }
}
