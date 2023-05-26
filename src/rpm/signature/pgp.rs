use super::traits;
use crate::errors::Error;
use crate::Timestamp;

use std::io;

use ::pgp::{composed::Deserializable, types::KeyTrait};

use ::pgp::packet::*;

/// Signer implementation using the `pgp` crate.
///
/// Note that this only supports ascii armored key files
/// commonly with the file extension `.asc` as generated
/// by i.e. `gpg`.
#[derive(Clone, Debug)]
pub struct Signer {
    secret_key: ::pgp::composed::signed_key::SignedSecretKey,
}

impl traits::Signing for Signer {
    type Signature = Vec<u8>;

    /// Despite the fact the API suggest zero copy pattern,
    /// it internally creates a copy until crate `pgp` provides
    /// a `Read` based implementation.
    fn sign(&self, data: impl io::Read, t: Timestamp) -> Result<Self::Signature, Error> {
        use ::chrono::offset::TimeZone;

        let t = ::chrono::offset::Utc
            .timestamp_opt(t.0.into(), 0)
            // "shouldn't fail as we are using 0 nanoseconds"
            .unwrap();

        let sig_cfg = SignatureConfig {
            version: SignatureVersion::V4,
            typ: SignatureType::Binary,
            pub_alg: self.secret_key.algorithm(),
            hash_alg: ::pgp::crypto::hash::HashAlgorithm::SHA2_256,
            issuer: Some(self.secret_key.key_id()),
            created: Some(t),
            unhashed_subpackets: vec![],
            hashed_subpackets: vec![
                Subpacket::critical(SubpacketData::SignatureCreationTime(t)),
                Subpacket::critical(SubpacketData::Issuer(self.secret_key.key_id())),
                //::pgp::packet::Subpacket::SignersUserID("rpm"), TODO this would be a nice addition
            ],
        };

        let passwd_fn = String::new;
        let signature_packet = sig_cfg
            .sign(&self.secret_key, passwd_fn, data)
            .map_err(|e| Error::SignError(Box::new(e)))?;

        let mut signature_bytes = Vec::with_capacity(1024);
        let mut cursor = io::Cursor::new(&mut signature_bytes);
        ::pgp::packet::write_packet(&mut cursor, &signature_packet)
            .map_err(|e| Error::SignError(Box::new(e)))?;

        Ok(signature_bytes)
    }
}

impl Signer {
    /// load the private key for signing
    pub fn load_from_asc_bytes(input: &[u8]) -> Result<Self, Error> {
        // only asc loading is supported right now
        let input = ::std::str::from_utf8(input).map_err(|e| Error::KeyLoadError {
            source: Box::new(e),
            details: "Failed to parse bytes as utf8 for ascii armored parsing",
        })?;
        Self::load_from_asc(input)
    }

    pub fn load_from_asc(input: &str) -> Result<Self, Error> {
        let (secret_key, _) = ::pgp::composed::signed_key::SignedSecretKey::from_string(input)
            .map_err(|e| Error::KeyLoadError {
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
    fn parse_signature(signature: &[u8]) -> Result<::pgp::packet::Signature, Error> {
        let mut cursor = io::Cursor::new(signature);
        let parser = ::pgp::packet::PacketParser::new(&mut cursor);
        let signature = parser
            .filter_map(|res| match res {
                Ok(::pgp::packet::Packet::Signature(sig_packet)) => Some(sig_packet),
                _ => None,
            })
            .next()
            .ok_or(Error::NoSignatureFound)?;
        Ok(signature)
    }
}

impl traits::Verifying for Verifier {
    type Signature = Vec<u8>;
    /// Despite the fact the API suggest zero copy pattern,
    /// it internally creates a copy until crate `pgp` provides
    /// a `Read` based implementation.
    fn verify(&self, mut data: impl io::Read, signature: &[u8]) -> Result<(), Error> {
        let signature = Self::parse_signature(signature)?;

        log::debug!("Signature issued by: {:?}", signature.issuer());

        if let Some(key_id) = signature.issuer() {
            log::trace!("Signature has issuer ref: {:?}", key_id);

            if self.public_key.key_id() == *key_id {
                return signature.verify(&self.public_key, data).map_err(|e| {
                    Error::VerificationError {
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
                    Err(Error::KeyNotFoundError {
                        key_ref: format!("{:?}", key_id),
                    }),
                    |previous_res, sub_key| {
                        if previous_res.is_err() {
                            log::trace!("Test next candidate subkey");
                            signature.verify(sub_key, &mut data).map_err(|e| {
                                Error::VerificationError {
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
                .map_err(|e| Error::VerificationError {
                    source: Box::new(e),
                    key_ref: format!("{:?}", self.public_key.key_id()),
                })
        }
    }
}

impl Verifier {
    pub fn load_from_asc_bytes(input: &[u8]) -> Result<Self, Error> {
        // only asc loading is supported right now
        let input = ::std::str::from_utf8(input).map_err(|e| Error::KeyLoadError {
            source: Box::new(e),
            details: "Failed to parse bytes as utf8 for ascii armored parsing",
        })?;
        Self::load_from_asc(input)
    }

    pub fn load_from_asc(input: &str) -> Result<Self, Error> {
        let (public_key, _) = ::pgp::composed::signed_key::SignedPublicKey::from_string(input)
            .map_err(|e| Error::KeyLoadError {
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
    use hex_literal::hex;

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

        let t = Timestamp(1_600_000_000);
        let signature = signer.sign(&mut cursor, t).expect("signed");
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
        use ::chrono::{TimeZone, Utc};
        use ::pgp::types::{PublicKeyTrait, SecretKeyTrait};

        const RPM_SHA2_256: [u8; 32] =
            hex!("d92bfe276e311a67fe128768c5df4d06fd461e043afdf872ba4c679d860db81e");

        let (signer, verifier) = prep();
        let (signing_key, verification_key) = { (signer.secret_key, verifier.public_key) };

        let passwd_fn = String::new;

        let digest = &RPM_SHA2_256[..];

        // stage 1: verify created signature is fine
        let signature = signing_key
            .create_signature(
                passwd_fn,
                ::pgp::crypto::hash::HashAlgorithm::SHA2_256,
                digest,
            )
            .expect("Failed to crate signature");

        verification_key
            .verify_signature(
                ::pgp::crypto::hash::HashAlgorithm::SHA2_256,
                digest,
                &signature,
            )
            .expect("Failed to validate signature");

        let sig_time = Utc.timestamp_opt(1_600_000_000, 0u32).unwrap();
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
                ::pgp::packet::Subpacket::critical(SubpacketData::SignatureCreationTime(sig_time)),
                ::pgp::packet::Subpacket::critical(SubpacketData::Issuer(signing_key.key_id())),
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
            .verify_signature(
                ::pgp::crypto::hash::HashAlgorithm::SHA2_256,
                digest,
                &signature,
            )
            .expect("Verify must succeed");
    }

    #[test]
    fn verify_pgp_crate2() {
        use ::chrono::{TimeZone, Utc};
        let (signer, verifier) = prep();

        let data = [1u8; 322];
        let data = &data[..];

        let passwd_fn = String::new;

        let sig_time = Utc.timestamp_opt(1_600_000_000, 0u32).unwrap();

        let sig_cfg = SignatureConfig {
            version: SignatureVersion::V4,
            typ: SignatureType::Binary,
            pub_alg: ::pgp::crypto::public_key::PublicKeyAlgorithm::RSA,
            hash_alg: ::pgp::crypto::hash::HashAlgorithm::SHA2_256,
            issuer: Some(signer.secret_key.key_id()),
            created: Some(sig_time),
            unhashed_subpackets: vec![],
            hashed_subpackets: vec![
                Subpacket::critical(SubpacketData::SignatureCreationTime(sig_time)),
                Subpacket::critical(SubpacketData::Issuer(signer.secret_key.key_id())),
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

        /// A sample signature extracted from rpm-sign using the test keys
        ///
        /// Should only be used for validating parsing.
        const RPM_SIGN_SIGNATURE: [u8; 536] = hex!(
            "8902150305005be98c5b24c6a8a7f4a80eb50108a84c0ffd1a9de30f7ebb74e3"
            "62effd4d1c11a168220dff4a721118e4b0466b1182c6d4d6db53641b32334195"
            "f30ca6c250ee81816a0805fa3b2666635cfa4b2502e7ad3f4f827aa34dad0da0"
            "196377d2183054c71423220b0dd8ba1b6c94b30fb382186233514eaafa848a4b"
            "cd8272f1409438c7bc48294f3298d9af351a0bf0877439d6e786449d5c7ade63"
            "1a16b2291d469e61adff916f51658ab9370e65b6772fb7746a9c8af04b2d87bf"
            "61ff70dc29ec9a0c7f12f655ea22b5f01a0da5e8c67f1b9c551b355cac722686"
            "8930d52d08930f9e1afd8c7edbca574fd942d7f674cdf668efe324669229da96"
            "878ea2882378eec3fc71fdb6366badd754554da0a3407051c276de9fa3e57f80"
            "72a9c37f3e37d77a9998c4c64b5193bcd0f29309737f6e7ab46b7b79e0455539"
            "fc61a7dea5ff80313914f6b6076cd7a410a087554de5a526c1990e5819aec3bf"
            "e81648e08596511872b80f009f26deec1232ecd03cde310bd6bf4ac5665ccdb0"
            "293c6dc61856d717b44debdcbbe44f1af5723a96444df314b17975a46acc9d27"
            "47a912a707a830aef2debc3387b58c053f454e644a866dc3f4fe059181952fad"
            "81da1b39f8f0b846f03882a6f235344d9e179a97afbd9b193188d83a502e9150"
            "45059288b207109a6c44a2720fca6817991a62cd66230f90a414a66c7d06c44b"
            "be814772ebd4a23d637386ef0e2b78d44f482eb0558c8e5d"
        );

        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("some.sig");
        println!("{}", path.display());

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
}
