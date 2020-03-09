use super::*;

#[macro_use]
use rsa;
use rsa::PublicKey;
use simple_asn1::oid;
use simple_asn1::{ASN1Block, BigUint, OID};

use num_bigint_dig;
use pem;
use rsa_der;
use sha2;

pub struct Signer {
    secret_key: rsa::RSAPrivateKey,
}

impl Signer {
    /// load the private key for signing
    pub fn load_secret_key(secret_key_der: &[u8]) -> Result<Self, RPMError> {
        // let secret_key_der = pem::parse(secret_key_pem)
        //     .map_err(|_e| RPMError::new("Failed to parse secret pem key"))?;

        let (n, e, d, p, q) = rsa_der::private_key_from_der(secret_key_der)
            .map_err(|_e| RPMError::new("Failed to parse secret inner der formatted key"))?;
        let secret_key = rsa::RSAPrivateKey::from_components(
            num_bigint_dig::BigUint::from_bytes_be(n.as_slice()),
            num_bigint_dig::BigUint::from_bytes_be(e.as_slice()),
            num_bigint_dig::BigUint::from_bytes_be(d.as_slice()),
            vec![
                num_bigint_dig::BigUint::from_bytes_be(p.as_slice()),
                num_bigint_dig::BigUint::from_bytes_be(q.as_slice()),
            ],
        );
        Ok(Self { secret_key })
    }

    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, RPMError> {
        let mut hasher = sha2::Sha256::default();
        hasher.input(data);
        let digest = hasher.result();

        let signature = self
            .secret_key
            .sign::<rsa::hash::Hashes>(rsa::PaddingScheme::PKCS1v15, None, &digest[..])
            .map_err(|_e| { dbg!(_e); RPMError::new("signing shall not fail") } )?;

        Ok(signature)
    }
}

pub struct Verifier {
    public_key: rsa::RSAPublicKey,
}

impl Verifier {
    /// load the public key for authenticity
    pub fn load_public_key(public_key_der: &[u8]) -> Result<Self, RPMError> {
        // let public_key =
        //     pem::parse(public_key).map_err(|_e| RPMError::new("failed to parse pem public key"))?;
        let (n, e) = rsa_der::public_key_from_der(public_key_der)
            .map_err(|_e| RPMError::new("failed to parse from der"))?;
        let n = num_bigint_dig::BigUint::from_bytes_be(n.as_slice());
        let e = num_bigint_dig::BigUint::from_bytes_be(e.as_slice());
        let public_key = rsa::RSAPublicKey::new(n, e)
            .map_err(|_e| RPMError::new("failed to construct key from n and e"))?;
        Ok(Self { public_key })
    }

    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), RPMError> {
        let mut hasher = sha2::Sha256::default();
        hasher.input(data);
        let digest = hasher.result();

        self.public_key
            .verify::<rsa::hash::Hashes>(rsa::PaddingScheme::PKCS1v15, None, &digest[..], signature)
            .map_err(|_e| RPMError::new("Failed to verify"))?;

        Ok(())
    }
}

/// signature bytes with signature type annotation
#[non_exhaustive]
pub(crate) enum SignatureDigest {
    Sha256(Vec<u8>),
    MD5(Vec<u8>),
    Sha1(Vec<u8>),
}

impl SignatureDigest {
    pub fn as_slice(&self) -> &[u8] {
        #[allow(unreachable_code, unreachable_patterns)]
        match self {
            Self::Sha256(x) => x.as_slice(),
            Self::MD5(x) => x.as_slice(),
            Self::Sha1(x) => x.as_slice(),
            _ => unreachable!("unknown variant"),
        }
    }
}

/// RFC4880 encoded signature
pub struct Rfc4880(Vec<u8>);

impl Rfc4880 {
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// ```asn1
/// DigestInfo ::= SEQUENCE {
///    digestAlgorithm DigestAlgorithm,
///    digest OCTET STRING
/// }
/// ```
///
/// https://tools.ietf.org/html/rfc8017#appendix-A.2.4
///
/// convert the raw digest to a rfc8017 DER `DigestInfo` struct
///
/// RFC-4880 section 13.1 and 5.2.2
pub fn raw_signature_to_rfc4880(digest: &[u8]) -> Result<Rfc4880, RPMError> {
    // TODO just use rsa::Hash::MD5.asn1_prefix()
    let sha256_oid = oid!(2, 16, 840, 1, 101, 3, 4, 2, 1);
    let _md5_oid = oid!(1, 2, 840, 113549, 2, 5);
    let _sha1_oid = oid!(1, 3, 14, 3, 2, 26);

    let digest_algorithm = ASN1Block::ObjectIdentifier(0, sha256_oid);
    let digest = ASN1Block::OctetString(0, digest.to_vec());

    let mut digest_info =
        simple_asn1::to_der(&ASN1Block::Sequence(0, vec![digest_algorithm, digest])).unwrap();

    // at least 8, and used to fill the desired length as needed
    // which in this case is as small as possible
    let mut ps = std::iter::repeat(0xFF).take(8).collect::<Vec<u8>>();
    // encode the length
    let mut encoded = Vec::with_capacity(digest_info.len() + 3 + ps.len());
    encoded.push(0x00);
    encoded.push(0x01);
    encoded.append(&mut ps);
    encoded.push(0x00);
    encoded.append(&mut digest_info);
    Ok(Rfc4880(encoded))
}

// TODO also return the type of the signature
// RFC-4880 section 13.1 and 5.2.2
pub(crate) fn raw_signature_from_rfc4880(rfc4880_data: &[u8]) -> Result<SignatureDigest, RPMError> {
    if rfc4880_data.len() < 11 {
        Err(RPMError::new("Message too short"))?;
    }
    if rfc4880_data[0] != 0x00 {
        Err(RPMError::new("byte 0 must be 0x00"))?;
    }
    if rfc4880_data[1] != 0x01 {
        Err(RPMError::new("byte 1 must be 0x01"))?;
    }
    let mut offset = 2;
    while offset < rfc4880_data.len() && rfc4880_data[offset] == 0xFF {
        offset += 1;
    }
    if offset < 10 {
        Err(RPMError::new("must contain at least 8 0xFF bytes"))?;
    }
    if rfc4880_data[offset] != 0x00 {
        Err(RPMError::new("byte n must be 0x00"))?;
    }

    println!("pre-amble {:#X?}", &rfc4880_data[..=offset]);

    offset += 1;

    println!("data {:#X?}", &rfc4880_data[offset..]);

    let blocks = simple_asn1::from_der(&rfc4880_data[offset..]).map_err(|e| {
        dbg!(e);
        RPMError::new("Failed to parse RFC4880 inner DER/ASN1")
    })?;

    match &blocks[0] {
        ASN1Block::Sequence(_, blocks) => {
            if blocks.len() != 2 {
                return Err(RPMError::new(
                    "Unexpected signature digest ASN1 block count",
                ));
            }

            let octets: Vec<u8> = match &blocks[1] {
                ASN1Block::OctetString(_, octets) => Ok(octets),
                _ => Err(RPMError::new("Not an octet string")),
            }?
            .clone();

            let _digest_algorithm = match &blocks[0] {
                ASN1Block::ObjectIdentifier(_, oid) => {
                    // utilize rsa::hash::Hash::SHA256.asn1_prefix()
                    return match oid {
                        x if x == md5_oid() => Ok(SignatureDigest::MD5(octets)),
                        x if x == sha1_oid() => Ok(SignatureDigest::Sha1(octets)),
                        x if x == sha256_oid() => Ok(SignatureDigest::Sha256(octets)),
                        _ => return Err(RPMError::new("Unknown OID")),
                    };
                }
                _ => return Err(RPMError::new("Failed")),
            };
        }
        _ => Err(RPMError::new("No signature in DER/ASN1")),
    }
}

use lazy_static::lazy_static;

pub(crate) fn md5_oid() -> &'static simple_asn1::OID {
    lazy_static! {
        static ref MD5_OID: simple_asn1::OID = oid!(1, 2, 840, 113549, 2, 5);
    }
    &MD5_OID
}

pub(crate) fn sha1_oid() -> &'static simple_asn1::OID {
    lazy_static! {
        static ref SHA1_OID: simple_asn1::OID = oid!(1, 3, 14, 3, 2, 26);
    }
    &SHA1_OID
}

pub(crate) fn sha256_oid() -> &'static simple_asn1::OID {
    lazy_static! {
        static ref SHA256_OID: simple_asn1::OID = oid!(2, 16, 840, 1, 101, 3, 4, 2, 1);
    }
    &SHA256_OID
}

#[cfg(test)]
mod test {
    use super::*;

    use ::rand::{thread_rng, Rng};
    use ::sha2::Sha256;

    /// equality check for static lookup from `rsa::hash::Hash` vs oid!() macro
    ///
    /// exists since we use oid!() for encoding but the static one for decoding
    #[test]
    fn oid_equiv() {
        use rsa::hash::{Hash, Hashes};

        let check = |oid: &OID, algo: Hashes| {
            let static_prefix = algo.asn1_prefix();
            // just the prefix without any payload bits
            // but the length already is calculated with the correct length
            // which is the last byte (for anything < 128 byte length)
            // which is all that RPM supports
            let payload_byte_count = *static_prefix.last().unwrap() as usize;

            let asn1 =
                // XXX correct encoding format according to RFC-4055 section 2.1
                ASN1Block::Sequence(0usize, vec![
                    ASN1Block::Sequence(0usize, vec![
                            ASN1Block::ObjectIdentifier(0usize, oid.clone()),
                            ASN1Block::Null(0usize),
                            // XXX must contain dummy data to force the correct lengths
                            ]),
                    ASN1Block::OctetString(0usize, vec![0u8;payload_byte_count])
                ]);
            let asn1repr =
            simple_asn1::to_der(&asn1)
                .map_err(|e| RPMError::new(format!("e == {:?}", e).as_str()))
                .unwrap();

            let generated = &asn1repr[0..(asn1repr.len() - payload_byte_count)]; 
            assert_eq!(generated, static_prefix.as_slice());
        };

        check(sha1_oid(), Hashes::SHA1);
        check(sha256_oid(), Hashes::SHA2_256);
        check(md5_oid(), Hashes::MD5);
    }

    #[test]
    fn rfc4880_roundtrip() {
        let mut rng = thread_rng();
        let mut data = vec![0u8; 500];
        rng.fill(&mut data[..]);

        let mut hasher = Sha256::new();
        hasher.input(&data[..]);
        let digest = hasher.result();

        println!("orig digest {:#X?}", &digest[..]);
        let encoded = raw_signature_to_rfc4880(&digest[..]).expect("Failed to encode rfc4880");
        println!("encoded {:#X?}", encoded.as_slice());
        let recovered_digest =
            raw_signature_from_rfc4880(encoded.as_slice()).expect("Failed to decode rfc4880");
        // println!("recov digest {:#X?}", &recovered_digest[..]);
        assert_eq!(recovered_digest.as_slice(), digest.as_slice());
    }



    #[test]
    fn sign_verify_round() -> Result<(), Box<dyn std::error::Error>> {
        use std::convert::From;
        use rand::rngs::OsRng;
        use rsa::{PaddingScheme, RSAPublicKey, RSAPrivateKey};
        use rsa_der;

        let mut rng = OsRng;
        let bits = 2048;
        let gpg_signing_key = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let gpg_signing_key2 = rsa_der::private_key_to_der(
            gpg_signing_key.n().to_bytes_be().as_slice(),
            gpg_signing_key.e().to_bytes_be().as_slice(),
            gpg_signing_key.d().to_bytes_be().as_slice(),
            gpg_signing_key.primes()[0].to_bytes_be().as_slice(),
            gpg_signing_key.primes()[1].to_bytes_be().as_slice(),
        );


        let verification_key = RSAPublicKey::from(gpg_signing_key);
        let gpg_signing_key = rsa_der::public_key_to_der(verification_key.n().to_bytes_be().as_slice(), verification_key.e().to_bytes_be().as_slice());


        let data = b"dfsdfjsd9ivnq320348934752312308205723900000580134850sdf";
        let digest_sha1 = sha1::Sha1::from(&data[..]);
        let digest_sha1 = digest_sha1.digest();

        let signer = Signer::load_secret_key(&gpg_signing_key2[..]).unwrap();
        let signature =  signer.sign(&digest_sha1.bytes()[..]).unwrap();


        let verifyer = Verifier::load_public_key(&gpg_signing_key[..]).unwrap();

        verifyer.verify(&digest_sha1.bytes()[..], &signature[..])?;
        Ok(())
    }
}
