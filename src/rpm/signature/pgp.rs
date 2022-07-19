use super::traits;
use crate::errors::RPMError;

use std::io::{Cursor, Read};

use ::pgp::{composed::Deserializable, types::KeyTrait};

use ::pgp::packet::*;

fn now() -> ::chrono::DateTime<::chrono::Utc> {
    // accuracy of serialized format is only down to seconds
    use ::chrono::offset::TimeZone;
    let now = ::chrono::offset::Utc::now();
    ::chrono::offset::Utc.timestamp(now.timestamp(), 0u32)
}

/// Signer implementation using the `pgp` crate.
///
/// Note that this only supports ascii armored key files
/// commonly with the file extension `.asc` as generated
/// by i.e. `gpg`.
#[derive(Clone, Debug)]
pub struct Signer {
    secret_key: ::pgp::composed::signed_key::SignedSecretKey,
}

impl traits::Signing<traits::algorithm::RSA> for Signer {
    type Signature = Vec<u8>;

    /// Despite the fact the API suggest zero copy pattern,
    /// it internally creates a copy until crate `pgp` provides
    /// a `Read` based implementation.
    fn sign<R: Read>(&self, data: R) -> Result<Self::Signature, RPMError> {
        let passwd_fn = String::new;

        let now = now();

        let sig_cfg = SignatureConfig {
            version: SignatureVersion::V4,
            typ: SignatureType::Binary,
            pub_alg: ::pgp::crypto::public_key::PublicKeyAlgorithm::RSA,
            hash_alg: ::pgp::crypto::hash::HashAlgorithm::SHA2_256,
            issuer: Some(self.secret_key.key_id()),
            created: Some(now),
            unhashed_subpackets: vec![],
            hashed_subpackets: vec![
                Subpacket::SignatureCreationTime(now),
                Subpacket::Issuer(self.secret_key.key_id()),
                //::pgp::packet::Subpacket::SignersUserID("rpm"), TODO this would be a nice addition
            ],
        };

        let signature_packet = sig_cfg
            .sign(&self.secret_key, passwd_fn, data)
            .map_err(|e| RPMError::SignError(Box::new(e)))?;

        let mut signature_bytes = Vec::with_capacity(1024);
        let mut cursor = Cursor::new(&mut signature_bytes);
        ::pgp::packet::write_packet(&mut cursor, &signature_packet)
            .map_err(|e| RPMError::SignError(Box::new(e)))?;

        Ok(signature_bytes)
    }
}

impl Signer {
    /// load the private key for signing
    pub fn load_from_asc_bytes(input: &[u8]) -> Result<Self, RPMError> {
        // only asc loading is supported right now
        let input = ::std::str::from_utf8(input).map_err(|e| RPMError::KeyLoadError {
            source: Box::new(e),
            details: "Failed to parse bytes as utf8 for ascii armored parsing",
        })?;
        Self::load_from_asc(input)
    }

    pub fn load_from_asc(input: &str) -> Result<Self, RPMError> {
        let (secret_key, _) = ::pgp::composed::signed_key::SignedSecretKey::from_string(input)
            .map_err(|e| RPMError::KeyLoadError {
                source: Box::new(e),
                details: "Failed to parse bytes as ascii armored key",
            })?;
        Ok(Self { secret_key })
    }
}

/// Verifier implementation using the `pgp` crate.
///
/// Note that this only supports ascii armored key files
/// commonly with the file extension `.asc` as generated
/// by i.e. `gpg`.
#[derive(Clone, Debug)]
pub struct Verifier {
    public_key: ::pgp::composed::signed_key::SignedPublicKey,
}

impl Verifier {
    fn parse_signature(signature: &[u8]) -> Result<::pgp::packet::Signature, RPMError> {
        let mut cursor = Cursor::new(signature);
        let parser = ::pgp::packet::PacketParser::new(&mut cursor);
        let signature = parser
            .filter_map(|res| match res {
                Ok(::pgp::packet::Packet::Signature(sig_packet)) => Some(sig_packet),
                _ => None,
            })
            .next()
            .ok_or(RPMError::NoSignatureFound)?;
        Ok(signature)
    }
}

impl traits::Verifying<traits::algorithm::RSA> for Verifier {
    type Signature = Vec<u8>;
    /// Despite the fact the API suggest zero copy pattern,
    /// it internally creates a copy until crate `pgp` provides
    /// a `Read` based implementation.
    fn verify<R: Read>(&self, mut data: R, signature: &[u8]) -> Result<(), RPMError> {
        let signature = Self::parse_signature(signature)?;

        log::debug!("Signature issued by: {:?}", signature.issuer());

        if let Some(key_id) = signature.issuer() {
            log::trace!("Signature has issuer ref: {:?}", key_id);

            if self.public_key.key_id() == *key_id {
                return signature.verify(&self.public_key, data).map_err(|e| {
                    RPMError::VerificationError {
                        source: Box::new(e),
                        key_ref: format!("{:?}", key_id),
                    }
                });
            } else {
                log::trace!(
                    "Signature issuer key id {:?} does not match primary keys key id: {:?}",
                    key_id,
                    self.public_key.key_id()
                );
            }

            self.public_key
                .public_subkeys
                .iter()
                .filter(|sub_key| {
                    if sub_key.key_id().as_ref() == key_id.as_ref() {
                        log::trace!(
                            "Found a matching key id {:?} == {:?}",
                            sub_key.key_id(),
                            key_id
                        );
                        true
                    } else {
                        log::trace!("Not the one we want: {:?}", sub_key);
                        false
                    }
                })
                .fold(
                    Err(RPMError::KeyNotFoundError {
                        key_ref: format!("{:?}", key_id),
                    }),
                    |previous_res, sub_key| {
                        if previous_res.is_err() {
                            log::trace!("Test next candidate subkey");
                            signature.verify(sub_key, &mut data).map_err(|e| {
                                RPMError::VerificationError {
                                    source: Box::new(e),
                                    key_ref: format!("{:?}", sub_key.key_id()),
                                }
                            })
                        } else {
                            log::trace!("Signature already verified, nop");
                            Ok(())
                        }
                    },
                )
        } else {
            log::trace!(
                "Signature has no issuer ref, attempting primary key: {:?}",
                self.public_key.primary_key.key_id()
            );
            signature
                .verify(&self.public_key, data)
                .map_err(|e| RPMError::VerificationError {
                    source: Box::new(e),
                    key_ref: format!("{:?}", self.public_key.key_id()),
                })
        }
    }
}

impl Verifier {
    pub fn load_from_asc_bytes(input: &[u8]) -> Result<Self, RPMError> {
        // only asc loading is supported right now
        let input = ::std::str::from_utf8(input).map_err(|e| RPMError::KeyLoadError {
            source: Box::new(e),
            details: "Failed to parse bytes as utf8 for ascii armored parsing",
        })?;
        Self::load_from_asc(input)
    }

    pub fn load_from_asc(input: &str) -> Result<Self, RPMError> {
        let (public_key, _) = ::pgp::composed::signed_key::SignedPublicKey::from_string(input)
            .map_err(|e| RPMError::KeyLoadError {
                source: Box::new(e),
                details: "Failed to parse bytes as ascii armored key",
            })?;

        Ok(Self { public_key })
    }
}

#[cfg(test)]
pub(crate) mod test {

    use super::super::{echo_signature, Signing, Verifying};
    use super::*;

    use super::Signer;
    use super::Verifier;

    fn prep() -> (Signer, Verifier) {
        let _ = env_logger::try_init();
        let (signing_key, verification_key) = load_asc_keys();
        let verifier =
            Verifier::load_from_asc_bytes(verification_key.as_slice()).expect("PK parsing failed");
        let signer =
            Signer::load_from_asc_bytes(signing_key.as_slice()).expect("PK parsing failed");
        (signer, verifier)
    }

    /// Load a pair of sample keys.
    pub(crate) fn load_asc_keys() -> (Vec<u8>, Vec<u8>) {
        let signing_key = include_bytes!("../../../test_assets/secret_key.asc");
        let verification_key = include_bytes!("../../../test_assets/public_key.asc");
        (signing_key.to_vec(), verification_key.to_vec())
    }

    #[test]
    fn parse_asc() {
        // assert `prep()` itself is sane
        let (signing_key, verification_key) = load_asc_keys();
        assert!(Signer::load_from_asc_bytes(signing_key.as_ref()).is_ok());
        assert!(Verifier::load_from_asc_bytes(verification_key.as_ref()).is_ok());
    }

    use std::io::Cursor;

    #[test]
    fn sign_verify_roundtrip() {
        let data = b"dfsdfjsd9ivnq320348934752312308205723900000580134850sdf";
        let mut cursor = Cursor::new(&data[..]);

        let (signer, verifier) = prep();

        let signature = signer.sign(&mut cursor).expect("signed");
        let signature = signature.as_slice();
        {
            // just to see if the previous already failed or not
            let _packet =
                Verifier::parse_signature(signature).expect("Created signature should be parsable");
        }

        echo_signature("test/roundtrip", signature);

        let mut cursor = Cursor::new(&data[..]);
        verifier
            .verify(&mut cursor, signature)
            .expect("failed to verify just signed signature");
    }

    #[test]
    fn verify_pgp_crate() {
        use ::pgp::types::{PublicKeyTrait, SecretKeyTrait};

        let (signer, verifier) = prep();
        let (signing_key, verification_key) = { (signer.secret_key, verifier.public_key) };

        let passwd_fn = || String::new();

        let digest = &RPM_SHA2_256[..];

        // stage 1: verify created signature is fine
        let signature = signing_key
            .create_signature(passwd_fn, ::pgp::crypto::HashAlgorithm::SHA2_256, digest)
            .expect("Failed to crate signature");

        verification_key
            .verify_signature(::pgp::crypto::HashAlgorithm::SHA2_256, digest, &signature)
            .expect("Failed to validate signature");

        // stage 2: check parsing success
        //
        let wrapped = ::pgp::Signature::new(
            ::pgp::types::Version::Old,
            ::pgp::packet::SignatureVersion::V4,
            ::pgp::packet::SignatureType::Binary,
            ::pgp::crypto::public_key::PublicKeyAlgorithm::RSA,
            ::pgp::crypto::hash::HashAlgorithm::SHA2_256,
            [digest[0], digest[1]],
            signature,
            vec![
                ::pgp::packet::Subpacket::SignatureCreationTime(now()),
                ::pgp::packet::Subpacket::Issuer(signing_key.key_id()),
                //::pgp::packet::Subpacket::SignersUserID("rpm"), TODO this would be a nice addition
            ],
            vec![],
        );

        let mut x = Vec::with_capacity(1024);

        let mut buff = Cursor::new(&mut x);
        ::pgp::packet::write_packet(&mut buff, &wrapped).expect("Write should be ok");

        log::debug!("{:02x?}", &x[0..15]);

        let signature =
            Verifier::parse_signature(x.as_slice()).expect("There is a signature for sure");
        assert_eq!(signature, wrapped);
        let signature = signature.signature;
        verification_key
            .verify_signature(::pgp::crypto::HashAlgorithm::SHA2_256, digest, &signature)
            .expect("Verify must succeed");
    }

    #[test]
    fn verify_pgp_crate2() {
        let (signer, verifier) = prep();

        let data = [1u8; 322];
        let data = &data[..];

        let passwd_fn = || String::new();

        let now = now();

        let sig_cfg = SignatureConfig {
            version: SignatureVersion::V4,
            typ: SignatureType::Binary,
            pub_alg: ::pgp::crypto::public_key::PublicKeyAlgorithm::RSA,
            hash_alg: ::pgp::crypto::hash::HashAlgorithm::SHA2_256,
            issuer: Some(signer.secret_key.key_id()),
            created: Some(now),
            unhashed_subpackets: vec![],
            hashed_subpackets: vec![
                Subpacket::SignatureCreationTime(now),
                Subpacket::Issuer(signer.secret_key.key_id()),
                //::pgp::packet::Subpacket::SignersUserID("rpm"), TODO this would be a nice addition
            ],
        };

        let signature_packet = sig_cfg
            .sign(&signer.secret_key, passwd_fn, data)
            .expect("Should sign");

        signature_packet
            .verify(&verifier.public_key, data)
            .expect("Failed to validate signature");
    }

    #[test]
    fn verify_subkeys_match() {
        // verifies that all subkeys are present in both keys under test_assets
        // which assures all other tests are sane
        use std::collections::HashSet;
        let (signer, verifier) = prep();
        let subkey_set = verifier.public_key.public_subkeys.iter().fold(
            HashSet::with_capacity(signer.secret_key.public_subkeys.len()),
            |mut acc, public_subkey| {
                log::debug!("public subkeys in public key: {:?}", public_subkey.key_id());
                acc.insert(public_subkey.key_id().as_ref().to_vec());
                acc
            },
        );
        signer
            .secret_key
            .secret_subkeys
            .iter()
            .for_each(|public_subkey| {
                log::debug!("secret subkeys in secret key: {:?}", public_subkey.key_id());
                assert!(subkey_set.contains(public_subkey.key_id().as_ref()));
            });
    }

    #[test]
    fn static_parse_rpm_sign_signature() {
        let _ = env_logger::try_init();

        std::fs::write(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("target")
                .join("some.sig"),
            &RPM_SIGN_SIGNATURE[..],
        )
        .expect("Should be able to dump extracted signature");

        let signature = &RPM_SIGN_SIGNATURE[..];
        let _signature = Verifier::parse_signature(signature).expect("It should load");
    }

    /// TODO fill with correct data
    const RPM_SHA2_256: [u8; 32] = [
        0xd9, 0x2b, 0xfe, 0x27, 0x6e, 0x31, 0x1a, 0x67, 0xfe, 0x12, 0x87, 0x68, 0xc5, 0xdf, 0x4d,
        0x06, 0xfd, 0x46, 0x1e, 0x04, 0x3a, 0xfd, 0xf8, 0x72, 0xba, 0x4c, 0x67, 0x9d, 0x86, 0x0d,
        0xb8, 0x1e,
    ];

    /// A sample signature extracted from rpm-sign using the test keys
    ///
    /// Should only be used for validating parsing.
    const RPM_SIGN_SIGNATURE: [u8; 536] = [
        0x89, 0x2, 0x15, 0x3, 0x5, 0x0, 0x5b, 0xe9, 0x8c, 0x5b, 0x24, 0xc6, 0xa8, 0xa7, 0xf4, 0xa8,
        0xe, 0xb5, 0x1, 0x8, 0xa8, 0x4c, 0xf, 0xfd, 0x1a, 0x9d, 0xe3, 0xf, 0x7e, 0xbb, 0x74, 0xe3,
        0x62, 0xef, 0xfd, 0x4d, 0x1c, 0x11, 0xa1, 0x68, 0x22, 0xd, 0xff, 0x4a, 0x72, 0x11, 0x18,
        0xe4, 0xb0, 0x46, 0x6b, 0x11, 0x82, 0xc6, 0xd4, 0xd6, 0xdb, 0x53, 0x64, 0x1b, 0x32, 0x33,
        0x41, 0x95, 0xf3, 0xc, 0xa6, 0xc2, 0x50, 0xee, 0x81, 0x81, 0x6a, 0x8, 0x5, 0xfa, 0x3b,
        0x26, 0x66, 0x63, 0x5c, 0xfa, 0x4b, 0x25, 0x2, 0xe7, 0xad, 0x3f, 0x4f, 0x82, 0x7a, 0xa3,
        0x4d, 0xad, 0xd, 0xa0, 0x19, 0x63, 0x77, 0xd2, 0x18, 0x30, 0x54, 0xc7, 0x14, 0x23, 0x22,
        0xb, 0xd, 0xd8, 0xba, 0x1b, 0x6c, 0x94, 0xb3, 0xf, 0xb3, 0x82, 0x18, 0x62, 0x33, 0x51,
        0x4e, 0xaa, 0xfa, 0x84, 0x8a, 0x4b, 0xcd, 0x82, 0x72, 0xf1, 0x40, 0x94, 0x38, 0xc7, 0xbc,
        0x48, 0x29, 0x4f, 0x32, 0x98, 0xd9, 0xaf, 0x35, 0x1a, 0xb, 0xf0, 0x87, 0x74, 0x39, 0xd6,
        0xe7, 0x86, 0x44, 0x9d, 0x5c, 0x7a, 0xde, 0x63, 0x1a, 0x16, 0xb2, 0x29, 0x1d, 0x46, 0x9e,
        0x61, 0xad, 0xff, 0x91, 0x6f, 0x51, 0x65, 0x8a, 0xb9, 0x37, 0xe, 0x65, 0xb6, 0x77, 0x2f,
        0xb7, 0x74, 0x6a, 0x9c, 0x8a, 0xf0, 0x4b, 0x2d, 0x87, 0xbf, 0x61, 0xff, 0x70, 0xdc, 0x29,
        0xec, 0x9a, 0xc, 0x7f, 0x12, 0xf6, 0x55, 0xea, 0x22, 0xb5, 0xf0, 0x1a, 0xd, 0xa5, 0xe8,
        0xc6, 0x7f, 0x1b, 0x9c, 0x55, 0x1b, 0x35, 0x5c, 0xac, 0x72, 0x26, 0x86, 0x89, 0x30, 0xd5,
        0x2d, 0x8, 0x93, 0xf, 0x9e, 0x1a, 0xfd, 0x8c, 0x7e, 0xdb, 0xca, 0x57, 0x4f, 0xd9, 0x42,
        0xd7, 0xf6, 0x74, 0xcd, 0xf6, 0x68, 0xef, 0xe3, 0x24, 0x66, 0x92, 0x29, 0xda, 0x96, 0x87,
        0x8e, 0xa2, 0x88, 0x23, 0x78, 0xee, 0xc3, 0xfc, 0x71, 0xfd, 0xb6, 0x36, 0x6b, 0xad, 0xd7,
        0x54, 0x55, 0x4d, 0xa0, 0xa3, 0x40, 0x70, 0x51, 0xc2, 0x76, 0xde, 0x9f, 0xa3, 0xe5, 0x7f,
        0x80, 0x72, 0xa9, 0xc3, 0x7f, 0x3e, 0x37, 0xd7, 0x7a, 0x99, 0x98, 0xc4, 0xc6, 0x4b, 0x51,
        0x93, 0xbc, 0xd0, 0xf2, 0x93, 0x9, 0x73, 0x7f, 0x6e, 0x7a, 0xb4, 0x6b, 0x7b, 0x79, 0xe0,
        0x45, 0x55, 0x39, 0xfc, 0x61, 0xa7, 0xde, 0xa5, 0xff, 0x80, 0x31, 0x39, 0x14, 0xf6, 0xb6,
        0x7, 0x6c, 0xd7, 0xa4, 0x10, 0xa0, 0x87, 0x55, 0x4d, 0xe5, 0xa5, 0x26, 0xc1, 0x99, 0xe,
        0x58, 0x19, 0xae, 0xc3, 0xbf, 0xe8, 0x16, 0x48, 0xe0, 0x85, 0x96, 0x51, 0x18, 0x72, 0xb8,
        0xf, 0x0, 0x9f, 0x26, 0xde, 0xec, 0x12, 0x32, 0xec, 0xd0, 0x3c, 0xde, 0x31, 0xb, 0xd6,
        0xbf, 0x4a, 0xc5, 0x66, 0x5c, 0xcd, 0xb0, 0x29, 0x3c, 0x6d, 0xc6, 0x18, 0x56, 0xd7, 0x17,
        0xb4, 0x4d, 0xeb, 0xdc, 0xbb, 0xe4, 0x4f, 0x1a, 0xf5, 0x72, 0x3a, 0x96, 0x44, 0x4d, 0xf3,
        0x14, 0xb1, 0x79, 0x75, 0xa4, 0x6a, 0xcc, 0x9d, 0x27, 0x47, 0xa9, 0x12, 0xa7, 0x7, 0xa8,
        0x30, 0xae, 0xf2, 0xde, 0xbc, 0x33, 0x87, 0xb5, 0x8c, 0x5, 0x3f, 0x45, 0x4e, 0x64, 0x4a,
        0x86, 0x6d, 0xc3, 0xf4, 0xfe, 0x5, 0x91, 0x81, 0x95, 0x2f, 0xad, 0x81, 0xda, 0x1b, 0x39,
        0xf8, 0xf0, 0xb8, 0x46, 0xf0, 0x38, 0x82, 0xa6, 0xf2, 0x35, 0x34, 0x4d, 0x9e, 0x17, 0x9a,
        0x97, 0xaf, 0xbd, 0x9b, 0x19, 0x31, 0x88, 0xd8, 0x3a, 0x50, 0x2e, 0x91, 0x50, 0x45, 0x5,
        0x92, 0x88, 0xb2, 0x7, 0x10, 0x9a, 0x6c, 0x44, 0xa2, 0x72, 0xf, 0xca, 0x68, 0x17, 0x99,
        0x1a, 0x62, 0xcd, 0x66, 0x23, 0xf, 0x90, 0xa4, 0x14, 0xa6, 0x6c, 0x7d, 0x6, 0xc4, 0x4b,
        0xbe, 0x81, 0x47, 0x72, 0xeb, 0xd4, 0xa2, 0x3d, 0x63, 0x73, 0x86, 0xef, 0xe, 0x2b, 0x78,
        0xd4, 0x4f, 0x48, 0x2e, 0xb0, 0x55, 0x8c, 0x8e, 0x5d,
    ];
}
