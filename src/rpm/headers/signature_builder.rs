//! signature index construction as builder pattern

use super::*;

use super::IndexEntry;
use crate::constants::*;
use std::default::Default;

/// A marker trait for builder stages
pub trait ConstructionStage {}

/// Initial empty builder.
pub struct Empty;
/// Builder beyond the empty stage, already containing a digest.
///
/// Implies that headers and content are complete.
pub struct WithDigest;

/// Builder already has a hash and is ready for completion.
pub struct WithSignature;

impl ConstructionStage for Empty {}

impl ConstructionStage for WithDigest {}

impl ConstructionStage for WithSignature {}

/// base signature header builder
///
/// T describes the stage and can be one of `Empty`, `WithDigest`, `WithSignature`
pub struct SignatureHeaderBuilder<T>
where
    T: ConstructionStage,
{
    entries: Vec<IndexEntry<IndexSignatureTag>>,
    phantom: std::marker::PhantomData<T>,
}

impl SignatureHeaderBuilder<Empty> {
    pub fn new() -> Self {
        Self {
            entries: Vec::with_capacity(10),
            phantom: Default::default(),
        }
    }
}

impl Default for SignatureHeaderBuilder<Empty> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> SignatureHeaderBuilder<T>
where
    T: ConstructionStage,
{
    /// Construct the complete signature header.
    pub fn build(self) -> Header<IndexSignatureTag> {
        Header::<IndexSignatureTag>::from_entries(
            self.entries,
            IndexSignatureTag::HEADER_SIGNATURES,
        )
    }
}

impl SignatureHeaderBuilder<Empty> {
    /// add a digest over the header and a signature across header and source excluding the static lead
    pub fn add_digest(mut self, digest_header_sha256: &str) -> SignatureHeaderBuilder<WithDigest> {
        let offset = 0i32; // filled externally later on
        self.entries.push(IndexEntry::new(
            IndexSignatureTag::RPMSIGTAG_SHA256,
            offset,
            IndexData::StringTag(digest_header_sha256.to_string()),
        ));
        SignatureHeaderBuilder::<WithDigest> {
            entries: self.entries,
            phantom: Default::default(),
        }
    }
}

impl SignatureHeaderBuilder<WithDigest> {
    /// add a signature over the header
    pub fn add_rsa_signature(
        mut self,
        sig_header_only: &[u8],
    ) -> SignatureHeaderBuilder<WithSignature> {
        let offset = 0i32; // filled externally later on
        self.entries.push(IndexEntry::new(
            IndexSignatureTag::RPMSIGTAG_RSA,
            offset,
            IndexData::Bin(sig_header_only.to_vec()),
        ));
        SignatureHeaderBuilder::<WithSignature> {
            entries: self.entries,
            phantom: Default::default(),
        }
    }

    pub fn add_eddsa_signature(
        mut self,
        sig_header_only: &[u8],
    ) -> SignatureHeaderBuilder<WithSignature> {
        let offset = 0i32; // filled externally later on
        self.entries.push(IndexEntry::new(
            IndexSignatureTag::RPMSIGTAG_DSA,
            offset,
            IndexData::Bin(sig_header_only.to_vec()),
        ));
        SignatureHeaderBuilder::<WithSignature> {
            entries: self.entries,
            phantom: Default::default(),
        }
    }

    pub fn add_ecdsa_signature(
        mut self,
        sig_header_only: &[u8],
    ) -> SignatureHeaderBuilder<WithSignature> {
        let offset = 0i32; // filled externally later on
        self.entries.push(IndexEntry::new(
            IndexSignatureTag::RPMSIGTAG_DSA,
            offset,
            IndexData::Bin(sig_header_only.to_vec()),
        ));
        SignatureHeaderBuilder::<WithSignature> {
            entries: self.entries,
            phantom: Default::default(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn signature_builder_w_digest_and_rsa_signature() {
        let builder = SignatureHeaderBuilder::<Empty>::new();
        let sig_header_only = [0u8; 32];
        let digest_header_sha256 = hex::encode([0u8; 64]);

        let header = builder
            .add_digest(digest_header_sha256.as_str())
            .add_rsa_signature(&sig_header_only[..])
            .build();

        assert!(
            header
                .find_entry_or_err(IndexSignatureTag::RPMSIGTAG_RSA)
                .is_ok()
        );
        assert!(
            header
                .find_entry_or_err(IndexSignatureTag::RPMSIGTAG_SHA256)
                .is_ok()
        );
    }

    #[test]
    fn signature_builder_w_digest_and_eddsa_signature() {
        let builder = SignatureHeaderBuilder::<Empty>::new();
        let sig_header_only = [0u8; 32];
        let digest_header_sha256: String = hex::encode([0u8; 64]);

        let header = builder
            .add_digest(digest_header_sha256.as_str())
            .add_eddsa_signature(&sig_header_only[..])
            .build();

        assert!(
            header
                .find_entry_or_err(IndexSignatureTag::RPMSIGTAG_DSA)
                .is_ok()
        );
        assert!(
            header
                .find_entry_or_err(IndexSignatureTag::RPMSIGTAG_SHA256)
                .is_ok()
        );
    }

    #[test]
    fn signature_builder_digest_only() {
        let builder = SignatureHeaderBuilder::<Empty>::new();
        let digest_header_sha256: String = hex::encode([0u8; 64]);
        let header = builder.add_digest(digest_header_sha256.as_str()).build();

        assert!(
            header
                .find_entry_or_err(IndexSignatureTag::RPMSIGTAG_RSA)
                .is_err()
        );
        assert!(
            header
                .find_entry_or_err(IndexSignatureTag::RPMSIGTAG_SHA256)
                .is_ok()
        );
    }

    // @todo: this test is kind of duplicative, probably not necessary?
    #[cfg(feature = "signature-meta")]
    #[test]
    fn signature_header_build() {
        let digest_header_sha256 =
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
        let sig_header_only: &[u8] = b"111222333444";

        let truth = {
            let offset = 0;
            let entries = vec![
                IndexEntry::new(
                    IndexSignatureTag::RPMSIGTAG_SHA256,
                    offset,
                    IndexData::StringTag(digest_header_sha256.to_owned()),
                ),
                IndexEntry::new(
                    IndexSignatureTag::RPMSIGTAG_RSA,
                    offset,
                    IndexData::Bin(sig_header_only.to_vec()),
                ),
            ];
            Header::<IndexSignatureTag>::from_entries(entries, IndexSignatureTag::HEADER_SIGNATURES)
        };

        let built = Header::<IndexSignatureTag>::builder()
            .add_digest(digest_header_sha256)
            .add_rsa_signature(sig_header_only)
            .build();

        assert_eq!(built, truth);
    }
}
