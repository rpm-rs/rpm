use sha2::Digest;

use super::headers::*;

use crate::constants::*;

use crate::errors::*;

use super::Lead;
use crate::crypto;
/// A complete rpm file.
///
/// Can either be created using the [`RPMPackageBuilder`](super::builder::RPMPackageBuilder)
/// or used with [`parse`](`self::RPMPackage::parse`) to obtain from a file.
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
    pub fn sign<S>(&mut self, signer: S) -> Result<(), RPMError>
    where
        S: crypto::Signing<crypto::algorithm::RSA, Signature = Vec<u8>>,
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

        let rsa_signature_spanning_header_only = signer.sign(header_bytes.as_slice())?;

        let rsa_signature_spanning_header_and_archive =
            signer.sign(header_and_content_bytes.as_slice())?;

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
    pub fn verify_signature<V>(&self, verifier: V) -> Result<(), RPMError>
    where
        V: crypto::Verifying<crypto::algorithm::RSA, Signature = Vec<u8>>,
    {
        // TODO retval should be SIGNATURE_VERIFIED or MISMATCH, not just an error

        let mut header_bytes = Vec::<u8>::with_capacity(1024);
        self.metadata.header.write(&mut header_bytes)?;

        let signature_header_only = self
            .metadata
            .signature
            .get_entry_binary_data(IndexSignatureTag::RPMSIGTAG_RSA)
            .map_err(|e| format!("Missing header-only signature / RPMSIGTAG_RSA: {:?}", e))?;

        crate::crypto::echo_signature("signature_header(header only)", signature_header_only);

        let signature_header_and_content = self
            .metadata
            .signature
            .get_entry_binary_data(IndexSignatureTag::RPMSIGTAG_PGP)
            .map_err(|e| format!("Missing header+content signature / RPMSIGTAG_PGP: {:?}", e))?;

        crate::crypto::echo_signature(
            "signature_header(header and content)",
            signature_header_and_content,
        );

        verifier
            .verify(header_bytes.as_slice(), signature_header_only)
            .map_err(|e| {
                format!(
                    "Failed to verify header-only signature / RPMSIGTAG_RSA: {:?}",
                    e
                )
            })?;

        let mut header_and_content_bytes =
            Vec::with_capacity(header_bytes.len() + self.content.len());
        header_and_content_bytes.extend(header_bytes);
        header_and_content_bytes.extend(self.content.as_slice());

        verifier
            .verify(
                header_and_content_bytes.as_slice(),
                signature_header_and_content,
            )
            .map_err(|e| {
                format!(
                    "Failed to verify header+content signature / RPMSIGTAG_PGP: {:?}",
                    e
                )
            })?;

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
    pub(crate) fn parse<T: std::io::BufRead>(input: &mut T) -> Result<Self, RPMError> {
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

    pub(crate) fn write<W: std::io::Write>(&self, out: &mut W) -> Result<(), RPMError> {
        self.lead.write(out)?;
        self.signature.write_signature(out)?;
        self.header.write(out)?;
        Ok(())
    }
}
